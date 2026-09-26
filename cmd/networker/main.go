package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tagptroll1/networker/frontend"
	"github.com/tagptroll1/networker/internal/api"
	"github.com/tagptroll1/networker/internal/capture"
	"github.com/tagptroll1/networker/internal/geo"
	"github.com/tagptroll1/networker/internal/history"
	"github.com/tagptroll1/networker/internal/names"
	"github.com/tagptroll1/networker/internal/router"
	"github.com/tagptroll1/networker/internal/tracker"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8765", "loopback HTTP address")
	city := flag.String("city-db", "", "path to GeoLite2-City.mmdb")
	asn := flag.String("asn-db", "", "optional path to GeoLite2-ASN.mmdb")
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		state = filepath.Join(os.Getenv("HOME"), ".local/state")
	}
	db := flag.String("db", filepath.Join(state, "networker", "history.db"), "history database")
	lat := flag.Float64("origin-lat", math.NaN(), "approximate map origin latitude")
	lon := flag.Float64("origin-lon", math.NaN(), "approximate map origin longitude")
	retention := flag.Duration("retention", 30*24*time.Hour, "how long to retain connection summaries")
	maxRecords := flag.Int("max-records", 50000, "maximum number of connection summaries")
	routerURL := flag.String("router-url", "", "optional RouterOS REST base URL, e.g. https://192.168.0.1")
	routerUser := flag.String("router-user", "networker", "RouterOS REST user")
	routerPassword := flag.String("router-password-file", "", "file holding the RouterOS REST password (/dev/stdin works)")
	routerCA := flag.String("router-ca", "", "PEM CA certificate that signed the router's HTTPS certificate")
	flag.Parse()
	if *retention <= 0 || *maxRecords <= 0 {
		log.Fatal("retention and max-records must be positive")
	}
	if !api.Loopback(*listen) {
		log.Fatal("-listen must be numeric loopback address and port")
	}
	if *city == "" {
		log.Fatal("-city-db is required")
	}
	if math.IsNaN(*lat) != math.IsNaN(*lon) {
		log.Fatal("set both origin coordinates or neither")
	}
	var origin *api.Origin
	if !math.IsNaN(*lat) {
		if math.IsInf(*lat, 0) || math.IsInf(*lon, 0) || *lat < -90 || *lat > 90 || *lon < -180 || *lon > 180 {
			log.Fatal("invalid origin coordinates")
		}
		origin = &api.Origin{Latitude: *lat, Longitude: *lon}
	}
	var gateway *router.Router
	if *routerURL != "" {
		if *routerPassword == "" || *routerCA == "" {
			log.Fatal("-router-url needs -router-password-file and -router-ca")
		}
		password, err := os.ReadFile(*routerPassword)
		if err != nil {
			log.Fatal(err)
		}
		ca, err := os.ReadFile(*routerCA)
		if err != nil {
			log.Fatal(err)
		}
		if gateway, err = router.New(*routerURL, *routerUser, strings.TrimRight(string(password), "\r\n"), ca); err != nil {
			log.Fatal(err)
		}
	}
	locations, err := geo.Open(*city, *asn)
	if err != nil {
		log.Fatal(err)
	}
	defer locations.Close()
	store, err := history.Open(*db)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	collector, err := capture.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer collector.Close()
	names := names.New()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		if err := collector.ReadDNS(ctx, func(ctx context.Context, query capture.DNSQuery, at time.Time) error {
			return store.AddDNS(ctx, history.DNSQuery{QueriedAt: at, Name: query.Name, Type: query.Type, ServerIP: query.ServerIP})
		}, names.Remember); err != nil && ctx.Err() == nil {
			log.Printf("capture DNS: %v", err)
		}
	}()
	defer func() { cancel(); <-dnsDone }()
	track := tracker.New(collector, store)
	server := &api.Server{Live: track, History: store, Names: names, Geo: locations, Origin: origin}
	if gateway != nil {
		server.Devices = gateway
		routerDone := make(chan struct{})
		go func() {
			defer close(routerDone)
			pollRouter(ctx, gateway, track, names)
		}()
		defer func() { cancel(); <-routerDone }()
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", server.Handler())
	mux.Handle("/", frontend.Handler())
	httpServer := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errors := make(chan error, 1)
	go func() { errors <- httpServer.ListenAndServe() }()
	log.Printf("networker listening at http://%s", *listen)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	prune := time.Now().Add(-time.Hour)
	for {
		select {
		case err := <-errors:
			if err != http.ErrServerClosed {
				log.Fatal(err)
			}
			return
		case <-ctx.Done():
			shutdown, done := context.WithTimeout(context.Background(), 3*time.Second)
			if err := httpServer.Shutdown(shutdown); err != nil {
				log.Print(err)
			}
			done()
			return
		case now := <-ticker.C:
			var ts unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
				log.Print(err)
				continue
			}
			if err := track.Poll(ctx, now, uint64(ts.Nano())); err != nil {
				log.Print(fmt.Errorf("poll traffic: %w", err))
			}
			if now.Sub(prune) >= time.Hour {
				if err := store.Prune(ctx, now.Add(-*retention), *maxRecords); err != nil {
					log.Printf("prune history: %v", err)
				}
				prune = now
			}
		}
	}
}

// pollRouter keeps router topology fresh and feeds other LAN devices'
// connections and the router's DNS cache into the tracker and name cache.
func pollRouter(ctx context.Context, gateway *router.Router, track *tracker.Tracker, cache *names.Cache) {
	var lastErr string
	report := func(err error) {
		// A failing router is logged once per distinct error, not every poll.
		if message := fmt.Sprint(err); err != nil && message != lastErr {
			log.Printf("router: %v", err)
			lastErr = message
		} else if err == nil && lastErr != "" {
			log.Print("router: reachable again")
			lastErr = ""
		}
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var refreshed time.Time
	for now := time.Now(); ; {
		err := func() error {
			if now.Sub(refreshed) >= time.Minute {
				if err := gateway.Refresh(ctx); err != nil {
					return err
				}
				answers, err := gateway.DNS(ctx)
				if err != nil {
					return err
				}
				cache.Remember(answers, now)
				refreshed = now
			}
			connections, err := gateway.Connections(ctx, hostAddress())
			if err != nil {
				return err
			}
			return track.SyncRouter(ctx, now, connections)
		}()
		if ctx.Err() != nil {
			return
		}
		report(err)
		select {
		case <-ctx.Done():
			return
		case now = <-ticker.C:
		}
	}
}

// hostAddress reports this machine's own addresses. The router also sees
// this host's traffic, but eBPF already records it with process details.
func hostAddress() func(netip.Addr) bool {
	own := make(map[netip.Addr]bool)
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("list host addresses: %v", err)
	}
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			own[prefix.Addr().Unmap()] = true
		}
	}
	return func(ip netip.Addr) bool { return own[ip] }
}
