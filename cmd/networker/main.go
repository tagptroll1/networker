package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
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
	"github.com/tagptroll1/networker/internal/snitch"
	"github.com/tagptroll1/networker/internal/tracker"
)

const procRoot = "/proc"

func main() {
	cfg, err := loadConfig(os.Environ(), frontend.Available)
	if err != nil {
		log.Fatal(err)
	}
	server := &api.Server{Origin: cfg.origin, Health: &api.Health{}, Names: names.New()}

	var gateway *router.Router
	if cfg.router.url != "" {
		password, err := os.ReadFile(cfg.router.passwordFile)
		if err != nil {
			log.Fatal(err)
		}
		ca, err := os.ReadFile(cfg.router.caFile)
		if err != nil {
			log.Fatal(err)
		}
		if gateway, err = router.New(cfg.router.url, cfg.router.user, strings.TrimRight(string(password), "\r\n"), ca); err != nil {
			log.Fatal(err)
		}
		server.Devices = gateway
	}
	if cfg.cityDB != "" {
		locations, err := geo.Open(cfg.cityDB, cfg.asnDB)
		if err != nil {
			log.Fatal(err)
		}
		defer locations.Close()
		server.Geo = locations
	}
	var records tracker.History = &history.Discard{}
	if cfg.history {
		store, err := history.Open(cfg.historyDB)
		if err != nil {
			log.Fatal(err)
		}
		defer store.Close()
		server.History, records = store, store
	}

	var collector *capture.Collector
	var source tracker.Source
	if cfg.capture {
		if collector, err = capture.Open(capture.Options{Enforce: cfg.enforce}); err != nil {
			log.Fatal(err)
		}
		defer collector.Close()
		source = collector
	}
	track := tracker.New(source, records)
	server.Live = track

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var policy *snitch.Policy
	remember := server.Names.Remember
	if cfg.snitch {
		var rules []snitch.Rule
		if cfg.rulesFile != "" {
			if rules, err = snitch.LoadRules(cfg.rulesFile); err != nil {
				log.Fatal(err)
			}
		}
		var enforcer snitch.Enforcer
		if cfg.enforce {
			enforcer = collector
		}
		policy = snitch.NewPolicy(rules, enforcer, func(pid uint32) string { return capture.Identify(procRoot, pid) })
		monitor, err := snitch.Open(snitch.Options{Path: cfg.snitchDB, Learn: cfg.learn, Watch: cfg.watch, Quiet: cfg.quiet,
			Retention: cfg.snitchKeep, MaxDestinations: cfg.snitchLimit}, policy)
		if err != nil {
			log.Fatal(err)
		}
		defer monitor.Close()
		server.Snitch = monitor
		remember = func(answers []capture.DNSAnswer, now time.Time) {
			server.Names.Remember(answers, now)
			policy.Answers(answers, now)
		}
		// Listening before Start, so a process started during the scan is not missed.
		eventsDone := make(chan struct{})
		go func() {
			defer close(eventsDone)
			err := collector.ReadEvents(ctx, func(event capture.Event) {
				if !event.Blocked {
					policy.Exec(event.PID)
					return
				}
				app := capture.Identify(procRoot, event.PID)
				if app == "" {
					app = "unknown"
				}
				monitor.Blocked(time.Now(), app, server.Names.Lookup(event.Addr), event.Addr)
			})
			if err != nil && ctx.Err() == nil {
				log.Printf("capture events: %v", err)
			}
		}()
		defer func() { cancel(); <-eventsDone }()
		if err := policy.Start(capture.Processes(procRoot)); err != nil {
			log.Fatal(err)
		}
		if cfg.enforce {
			log.Printf("snitch: enforcing %d rules", len(rules))
		} else if len(rules) != 0 {
			log.Printf("snitch: dry run, %d rules only flag matches", len(rules))
		}
	}

	if cfg.capture {
		ignore := func(context.Context, capture.DNSQuery, time.Time) error { return nil }
		save := ignore
		if cfg.history {
			save = func(ctx context.Context, query capture.DNSQuery, at time.Time) error {
				return server.History.AddDNS(ctx, history.DNSQuery{QueriedAt: at, Name: query.Name, Type: query.Type, ServerIP: query.ServerIP})
			}
		}
		dnsDone := make(chan struct{})
		go func() {
			defer close(dnsDone)
			if err := collector.ReadDNS(ctx, save, remember); err != nil && ctx.Err() == nil {
				log.Printf("capture DNS: %v", err)
				server.Health.DNSFailed(err)
			}
		}()
		defer func() { cancel(); <-dnsDone }()
	}
	if gateway != nil {
		routerDone := make(chan struct{})
		go func() {
			defer close(routerDone)
			pollRouter(ctx, gateway, track, remember, cfg.capture)
		}()
		defer func() { cancel(); <-routerDone }()
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", server.Handler())
	if cfg.dashboard {
		mux.Handle("/", frontend.Handler())
	}
	httpServer := &http.Server{Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errors := make(chan error, 1)
	go func() { errors <- httpServer.ListenAndServe() }()
	log.Printf("networker listening at http://%s", cfg.listen)

	// A persistent failure would otherwise log every second.
	var logged string
	var loggedAt time.Time
	failed := func(now time.Time, err error) {
		server.Health.PollFailed(err)
		if message := err.Error(); message != logged || now.Sub(loggedAt) >= time.Minute {
			log.Printf("poll traffic: %s", message)
			logged, loggedAt = message, now
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	prune := time.Now().Add(-time.Hour)
	for {
		select {
		case err := <-errors:
			if err != http.ErrServerClosed {
				cancel()
				log.Print(err)
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
			if cfg.capture {
				var ts unix.Timespec
				if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
					failed(now, err)
					continue
				}
				if err := track.Poll(ctx, now, uint64(ts.Nano())); err != nil {
					failed(now, fmt.Errorf("poll traffic: %w", err))
					continue
				}
				if logged != "" {
					log.Print("poll traffic recovered")
					logged = ""
				}
			}
			server.Health.PollOK(now)
			if server.Snitch != nil {
				live := track.Live(now)
				seen := make([]snitch.Seen, 0, len(live))
				for _, flow := range live {
					seen = append(seen, snitch.Seen{Flow: flow, Host: server.Names.Lookup(flow.Remote.Addr())})
				}
				server.Snitch.Observe(now, seen)
				policy.Sweep(now)
				if err := server.Snitch.Tick(ctx, now); err != nil && ctx.Err() == nil {
					log.Printf("save snitch: %v", err)
				}
			}
			if server.History != nil && now.Sub(prune) >= time.Hour {
				if err := server.History.Prune(ctx, now.Add(-cfg.retention), cfg.maxRecords); err != nil {
					log.Printf("prune history: %v", err)
				}
				prune = now
			}
		}
	}
}

// pollRouter keeps router topology fresh and feeds other LAN devices'
// connections and the router's DNS cache into the tracker and name cache.
func pollRouter(ctx context.Context, gateway *router.Router, track *tracker.Tracker, remember func([]capture.DNSAnswer, time.Time), capturing bool) {
	// Without capture nothing else records this host, so the router view keeps it.
	skip := func(netip.Addr) bool { return false }
	if capturing {
		skip = hostAddress()
	}
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
				remember(answers, now)
				refreshed = now
			}
			connections, err := gateway.Connections(ctx, skip)
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
