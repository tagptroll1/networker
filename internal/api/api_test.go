package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tagptroll1/networker/internal/capture"
	"github.com/tagptroll1/networker/internal/geo"
	"github.com/tagptroll1/networker/internal/history"
	"github.com/tagptroll1/networker/internal/names"
	"github.com/tagptroll1/networker/internal/tracker"
)

type locations struct{}

func (locations) Find(netip.Addr) *geo.Location { return nil }

type source struct{ flows []capture.Flow }

func (s source) Snapshot() ([]capture.Flow, error) { return s.flows, nil }

func TestFlowIncludesObservedDomain(t *testing.T) {
	db, err := history.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ip := netip.MustParseAddr("203.0.113.42")
	cache := names.New()
	cache.Remember([]capture.DNSAnswer{{Name: "example.com", Address: ip, TTL: time.Minute}}, time.Now())
	track := tracker.New(source{[]capture.Flow{{Key: capture.Key{
		Local: netip.MustParseAddrPort("192.0.2.1:12345"), Remote: netip.AddrPortFrom(ip, 443), Protocol: 6,
	}, Ready: true}}}, db)
	if err := track.Poll(context.Background(), time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	srv := (&Server{Live: track, History: db, Geo: locations{}, Names: cache}).Handler()
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/flows", nil))
	var flows []struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &flows); err != nil || len(flows) != 1 || flows[0].Domain != "example.com" {
		t.Fatalf("flow domains: %+v %v", flows, err)
	}
}

func TestEndpoints(t *testing.T) {
	db, err := history.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.AddDNS(context.Background(), history.DNSQuery{QueriedAt: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC), Name: "example.com", Type: "A", ServerIP: netip.MustParseAddr("127.0.0.53")}); err != nil {
		t.Fatal(err)
	}
	srv := (&Server{Live: tracker.New(nil, db), History: db, Geo: locations{}}).Handler()
	for _, endpoint := range []string{"/api/flows", "/api/connections", "/api/dns", "/api/config"} {
		response := httptest.NewRecorder()
		srv.ServeHTTP(response, httptest.NewRequest("GET", endpoint, nil))
		if response.Code != 200 {
			t.Fatalf("%s: %d", endpoint, response.Code)
		}
		var data any
		if err := json.Unmarshal(response.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
	}
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/connections?since=wrong", nil))
	if response.Code != 400 {
		t.Fatal("invalid time accepted")
	}
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/dns?limit=1", nil))
	var queries []history.DNSQuery
	if err := json.Unmarshal(response.Body.Bytes(), &queries); err != nil || len(queries) != 1 || queries[0].Name != "example.com" {
		t.Fatalf("DNS response: %+v %v", queries, err)
	}
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/dns?limit=501", nil))
	if response.Code != 400 {
		t.Fatal("invalid DNS limit accepted")
	}
}

func TestLoopback(t *testing.T) {
	if !Loopback("127.0.0.1:8765") || !Loopback("[::1]:8765") || Loopback("0.0.0.0:8765") || Loopback("localhost:8765") {
		t.Fatal("only numeric loopback hosts are allowed")
	}
}

type devices map[netip.Addr]history.Device

func (d devices) Lookup(ip netip.Addr) *history.Device {
	if device, ok := d[ip]; ok {
		return &device
	}
	return nil
}

func TestRouterDevices(t *testing.T) {
	db, err := history.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	host, tv := netip.MustParseAddr("192.168.10.20"), netip.MustParseAddr("192.168.20.20")
	track := tracker.New(source{[]capture.Flow{{Key: capture.Key{
		Local: netip.AddrPortFrom(host, 40000), Remote: netip.AddrPortFrom(tv, 8009), Protocol: 6,
	}, Ready: true}}}, db)
	if err := track.Poll(context.Background(), time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	srv := (&Server{Live: track, History: db, Geo: locations{}, Devices: devices{
		host: {IP: host, Name: "desktop", VLAN: 10}, tv: {IP: tv, Name: "Living-Room-TV", VLAN: 20},
	}}).Handler()
	var flows []struct {
		Source string          `json:"source"`
		Domain string          `json:"domain"`
		Device *history.Device `json:"device"`
	}
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/flows", nil))
	if err := json.Unmarshal(response.Body.Bytes(), &flows); err != nil || len(flows) != 1 || flows[0].Source != "host" ||
		flows[0].Domain != "Living-Room-TV" || flows[0].Device == nil || flows[0].Device.VLAN != 10 {
		t.Fatalf("flows: %+v %v", flows, err)
	}
	var connections []struct {
		Source string          `json:"source"`
		Device *history.Device `json:"device"`
	}
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/connections", nil))
	if err := json.Unmarshal(response.Body.Bytes(), &connections); err != nil || len(connections) != 1 || connections[0].Source != "host" ||
		connections[0].Device == nil || connections[0].Device.Name != "desktop" {
		t.Fatalf("connections: %+v %v", connections, err)
	}
	var config struct {
		Router bool `json:"router"`
	}
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/config", nil))
	if err := json.Unmarshal(response.Body.Bytes(), &config); err != nil || !config.Router {
		t.Fatalf("config: %+v %v", config, err)
	}
}

func TestLabels(t *testing.T) {
	db, err := history.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	host, tv := netip.MustParseAddr("192.168.10.20"), netip.MustParseAddr("192.168.20.20")
	track := tracker.New(source{[]capture.Flow{{Key: capture.Key{
		Local: netip.AddrPortFrom(host, 40000), Remote: netip.AddrPortFrom(tv, 8009), Protocol: 6,
	}, Ready: true}}}, db)
	if err := track.Poll(context.Background(), time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	srv := (&Server{Live: track, History: db, Geo: locations{}, Devices: devices{
		host: {IP: host, Name: "desktop", VLAN: 10}, tv: {IP: tv, Name: "Living-Room-TV", VLAN: 20},
	}}).Handler()
	put := func(path, body string, headers map[string]string) int {
		request := httptest.NewRequest("PUT", path, strings.NewReader(body))
		request.Host = "127.0.0.1:8765"
		request.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response := httptest.NewRecorder()
		srv.ServeHTTP(response, request)
		return response.Code
	}
	for _, c := range []struct {
		path, body string
		headers    map[string]string
		want       int
	}{
		{"/api/labels/vlan/10", `{"name":" Office "}`, map[string]string{"Origin": "http://127.0.0.1:8765"}, 204},
		{"/api/labels/ip/192.168.20.20", `{"name":"Living room TV"}`, nil, 204},
		{"/api/labels/ip/192.168.10.20", `{"name":"Workstation"}`, nil, 204},
		{"/api/labels/ip/192.168.10.20", `{"name":"x"}`, map[string]string{"Origin": "https://evil.example"}, 403},
		{"/api/labels/ip/192.168.10.20", `{"name":"x"}`, map[string]string{"Content-Type": "text/plain"}, 415},
		{"/api/labels/vlan/4095", `{"name":"x"}`, nil, 400},
		{"/api/labels/ip/not-an-ip", `{"name":"x"}`, nil, 400},
		{"/api/labels/vlan/20", `{"name":"x","extra":1}`, nil, 400},
		{"/api/labels/vlan/20", `{"name":"` + strings.Repeat("x", 65) + `"}`, nil, 400},
		{"/api/labels/vlan/20", `{"name":"a\u0007b"}`, nil, 400},
	} {
		if got := put(c.path, c.body, c.headers); got != c.want {
			t.Fatalf("%s %s %v: %d, want %d", c.path, c.body, c.headers, got, c.want)
		}
	}
	// A DNS-rebound page reaches the server under another Host.
	request := httptest.NewRequest("PUT", "/api/labels/vlan/20", strings.NewReader(`{"name":"x"}`))
	request.Host = "evil.example:8765"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatalf("rebound host: %d", response.Code)
	}
	var flows []struct {
		Domain string          `json:"domain"`
		Device *history.Device `json:"device"`
	}
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/flows", nil))
	if err := json.Unmarshal(response.Body.Bytes(), &flows); err != nil || len(flows) != 1 || flows[0].Domain != "Living room TV" ||
		flows[0].Device.VLANName != "Office" || flows[0].Device.Label != "Workstation" {
		t.Fatalf("labelled flows: %+v %v", flows, err)
	}
	// An empty name removes the label.
	if got := put("/api/labels/ip/192.168.10.20", `{"name":""}`, nil); got != 204 {
		t.Fatal(got)
	}
	var labels struct {
		VLANs map[string]string `json:"vlans"`
		IPs   map[string]string `json:"ips"`
	}
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/labels", nil))
	if err := json.Unmarshal(response.Body.Bytes(), &labels); err != nil || labels.VLANs["10"] != "Office" || labels.IPs["192.168.20.20"] != "Living room TV" || len(labels.IPs) != 1 {
		t.Fatalf("labels: %+v %v", labels, err)
	}
	var stored []struct {
		RemoteName string          `json:"remote_name"`
		Device     *history.Device `json:"device"`
	}
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, httptest.NewRequest("GET", "/api/connections", nil))
	if err := json.Unmarshal(response.Body.Bytes(), &stored); err != nil || len(stored) != 1 || stored[0].RemoteName != "Living room TV" ||
		stored[0].Device.VLANName != "Office" || stored[0].Device.Label != "" || stored[0].Device.Name != "desktop" {
		t.Fatalf("labelled history: %+v %v", stored, err)
	}
}
