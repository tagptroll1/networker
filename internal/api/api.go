package api

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tagptroll1/networker/internal/geo"
	"github.com/tagptroll1/networker/internal/history"
	"github.com/tagptroll1/networker/internal/names"
	"github.com/tagptroll1/networker/internal/tracker"
)

type Origin struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type Server struct {
	Live    *tracker.Tracker
	History *history.Store
	Names   *names.Cache
	Geo     interface {
		Find(netip.Addr) *geo.Location
	}
	Origin *Origin
	// Devices describes LAN addresses when router integration is enabled.
	Devices interface {
		Lookup(netip.Addr) *history.Device
	}
}

type connection struct {
	history.Connection
	Location   *geo.Location `json:"location"`
	RemoteName string        `json:"remote_name,omitempty"`
}

type flow struct {
	tracker.Flow
	Location *geo.Location `json:"location"`
	Domain   string        `json:"domain,omitempty"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		respond(w, struct {
			Origin *Origin `json:"origin"`
			Router bool    `json:"router"`
		}{s.Origin, s.Devices != nil})
	})
	mux.HandleFunc("GET /api/flows", func(w http.ResponseWriter, r *http.Request) {
		flows, err := s.flows(r.Context())
		if err != nil {
			http.Error(w, "could not read labels", http.StatusInternalServerError)
			return
		}
		respond(w, flows)
	})
	mux.HandleFunc("GET /api/connections", func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 500 {
				http.Error(w, "limit must be 1..500", http.StatusBadRequest)
				return
			}
			limit = n
		}
		since := time.Unix(0, 0)
		if v := r.URL.Query().Get("since"); v != "" {
			var err error
			since, err = time.Parse(time.RFC3339, v)
			if err != nil {
				http.Error(w, "since must be RFC3339", http.StatusBadRequest)
				return
			}
		}
		records, err := s.History.List(r.Context(), since, limit)
		if err != nil {
			http.Error(w, "could not read history", http.StatusInternalServerError)
			return
		}
		labels, err := s.History.Labels(r.Context())
		if err != nil {
			http.Error(w, "could not read labels", http.StatusInternalServerError)
			return
		}
		result := make([]connection, 0, len(records))
		for _, record := range records {
			if record.Device == nil {
				if local, err := netip.ParseAddrPort(record.Local); err == nil {
					record.Device = s.lookup(local.Addr())
				}
			}
			record.Device = named(labels, record.Device)
			remoteName := labels.IPs[record.RemoteIP]
			if remote := s.lookup(record.RemoteIP); remoteName == "" && remote != nil {
				remoteName = remote.Name
			}
			result = append(result, connection{record, s.Geo.Find(record.RemoteIP), remoteName})
		}
		respond(w, result)
	})
	mux.HandleFunc("GET /api/dns", func(w http.ResponseWriter, r *http.Request) {
		limit := 100
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 500 {
				http.Error(w, "limit must be 1..500", http.StatusBadRequest)
				return
			}
			limit = n
		}
		since := time.Unix(0, 0)
		if v := r.URL.Query().Get("since"); v != "" {
			var err error
			since, err = time.Parse(time.RFC3339, v)
			if err != nil {
				http.Error(w, "since must be RFC3339", http.StatusBadRequest)
				return
			}
		}
		queries, err := s.History.ListDNS(r.Context(), since, limit)
		if err != nil {
			http.Error(w, "could not read DNS history", http.StatusInternalServerError)
			return
		}
		respond(w, queries)
	})
	mux.HandleFunc("GET /api/labels", func(w http.ResponseWriter, r *http.Request) {
		labels, err := s.History.Labels(r.Context())
		if err != nil {
			http.Error(w, "could not read labels", http.StatusInternalServerError)
			return
		}
		respond(w, labels)
	})
	mux.HandleFunc("PUT /api/labels/vlan/{vlan}", func(w http.ResponseWriter, r *http.Request) {
		vlan, err := strconv.ParseUint(r.PathValue("vlan"), 10, 16)
		if err != nil || vlan < 1 || vlan > 4094 {
			http.Error(w, "vlan must be 1..4094", http.StatusBadRequest)
			return
		}
		s.setLabel(w, r, func(name string) error { return s.History.SetVLANLabel(r.Context(), uint16(vlan), name) })
	})
	mux.HandleFunc("PUT /api/labels/ip/{ip}", func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(r.PathValue("ip"))
		if err != nil || ip.Zone() != "" {
			http.Error(w, "ip must be an IPv4 or IPv6 address", http.StatusBadRequest)
			return
		}
		s.setLabel(w, r, func(name string) error { return s.History.SetIPLabel(r.Context(), ip, name) })
	})
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		send := func() bool {
			flows, err := s.flows(r.Context())
			if err != nil {
				return false
			}
			data, err := json.Marshal(flows)
			if err != nil {
				return false
			}
			_, err = w.Write(append(append([]byte("event: flows\ndata: "), data...), '\n', '\n'))
			if err == nil {
				w.(http.Flusher).Flush()
			}
			return err == nil
		}
		if !send() {
			return
		}
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if !send() {
					return
				}
			}
		}
	})
	return mux
}

func (s *Server) flows(ctx context.Context) ([]flow, error) {
	labels, err := s.History.Labels(ctx)
	if err != nil {
		return nil, err
	}
	live := s.Live.Live(time.Now())
	result := make([]flow, 0, len(live))
	for _, item := range live {
		name := ""
		if s.Names != nil && item.Direction == "outbound" {
			name = s.Names.Lookup(item.Remote.Addr())
		}
		// Another LAN device is named by its DHCP lease.
		if remote := s.lookup(item.Remote.Addr()); name == "" && remote != nil {
			name = remote.Name
		}
		// This host's own device, so its VLAN shows beside other devices'.
		if item.Device == nil {
			item.Device = s.lookup(item.Local.Addr())
		}
		item.Device = named(labels, item.Device)
		// The user's own name for an address wins over DNS and DHCP names.
		if label := labels.IPs[item.Remote.Addr().Unmap()]; label != "" {
			name = label
		}
		result = append(result, flow{item, s.Geo.Find(item.Remote.Addr()), name})
	}
	return result, nil
}

// named applies the user's labels to a copy, since devices are shared with the tracker.
func named(labels history.Labels, device *history.Device) *history.Device {
	if device == nil {
		return nil
	}
	d := *device
	d.Label = labels.IPs[d.IP]
	if d.VLAN != 0 {
		d.VLANName = labels.VLANs[d.VLAN]
	}
	return &d
}

func (s *Server) lookup(ip netip.Addr) *history.Device {
	if s.Devices == nil {
		return nil
	}
	return s.Devices.Lookup(ip)
}

// setLabel handles a label write. Only the dashboard itself may write: a JSON
// body forces a CORS preflight that other sites cannot pass, and Host and
// Origin must be this loopback server, which also stops DNS rebinding.
func (s *Server) setLabel(w http.ResponseWriter, r *http.Request, save func(string) error) {
	host, err := netip.ParseAddrPort(r.Host)
	if err != nil || !host.Addr().IsLoopback() || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+r.Host) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mediaType != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		http.Error(w, "body must be {\"name\": string}", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if utf8.RuneCountInString(name) > 64 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		http.Error(w, "name must be at most 64 characters without control characters", http.StatusBadRequest)
		return
	}
	if err := save(name); err != nil {
		http.Error(w, "could not save label", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}

// Public endpoints have no authentication; caller must bind loopback only.
func Loopback(address string) bool {
	addr, err := netip.ParseAddrPort(address)
	return err == nil && addr.Addr().IsLoopback()
}
