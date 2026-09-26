package router

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// Shapes follow RouterOS 7.24 REST output: every value is a string.
var sample = map[string]string{
	"/rest/ip/address": `[{"address":"192.168.10.1/24","interface":"Management","disabled":"false","invalid":"false"},
		{"address":"10.0.0.1/24","interface":"Servers","disabled":"false","invalid":"false"},
		{"address":"192.168.88.1/24","interface":"bridge","disabled":"false","invalid":"false"},
		{"address":"198.51.100.216/24","interface":"ether1","disabled":"false","invalid":"false"}]`,
	"/rest/interface/vlan":        `[{"name":"Management","vlan-id":"10"},{"name":"Servers","vlan-id":"100"}]`,
	"/rest/interface/bridge":      `[{"name":"bridge","pvid":"1","vlan-filtering":"true"}]`,
	"/rest/interface/list/member": `[{"list":"LAN","interface":"bridge","disabled":"false"},{"list":"WAN","interface":"ether1","disabled":"false"}]`,
	"/rest/ip/dhcp-server/lease": `[{"address":"192.168.10.21","mac-address":"AA:BB:CC:00:00:39","host-name":"laptop"},
		{"address":"10.0.0.50","mac-address":"AA:BB:CC:00:00:50","comment":"Media server","host-name":"nas"},
		{"address":"192.168.10.20","mac-address":"AA:BB:CC:00:01:79","host-name":"desktop"}]`,
	"/rest/ip/firewall/connection": `[
		{".id":"*1","protocol":"tcp","src-address":"192.168.10.21","src-port":"64356","dst-address":"17.57.146.139","dst-port":"5223","reply-src-address":"17.57.146.139","reply-src-port":"5223","reply-dst-address":"198.51.100.216","reply-dst-port":"64356","orig-bytes":"674347","repl-bytes":"1406539","tcp-state":"established"},
		{".id":"*2","protocol":"tcp","src-address":"192.168.10.20","src-port":"34956","dst-address":"160.79.104.10","dst-port":"443","reply-src-address":"160.79.104.10","reply-src-port":"443","reply-dst-address":"198.51.100.216","reply-dst-port":"34956","orig-bytes":"1","repl-bytes":"2","tcp-state":"established"},
		{".id":"*3","protocol":"udp","src-address":"192.168.10.21","src-port":"50529","dst-address":"192.168.10.1","dst-port":"53","reply-src-address":"192.168.10.1","reply-src-port":"53","reply-dst-address":"192.168.10.21","reply-dst-port":"50529","orig-bytes":"144","repl-bytes":"474"},
		{".id":"*4","protocol":"tcp","src-address":"203.0.113.9","src-port":"40000","dst-address":"198.51.100.216","dst-port":"443","reply-src-address":"10.0.0.50","reply-src-port":"8443","reply-dst-address":"203.0.113.9","reply-dst-port":"40000","orig-bytes":"100","repl-bytes":"9000","tcp-state":"syn-received"},
		{".id":"*5","protocol":"icmp","src-address":"192.168.10.21","dst-address":"1.1.1.1","reply-src-address":"1.1.1.1","reply-dst-address":"198.51.100.216","orig-bytes":"84","repl-bytes":"84"},
		{".id":"*6","protocol":"udp","src-address":"198.51.100.216","src-port":"5000","dst-address":"1.1.1.1","dst-port":"53","reply-src-address":"1.1.1.1","reply-src-port":"53","reply-dst-address":"198.51.100.216","reply-dst-port":"5000","orig-bytes":"70","repl-bytes":"90"},
		{".id":"*7","protocol":"udp","src-address":"10.0.0.50","src-port":"5405","dst-address":"192.168.10.21","dst-port":"5405","reply-src-address":"192.168.10.21","reply-src-port":"5405","reply-dst-address":"10.0.0.50","reply-dst-port":"5405","orig-bytes":"10","repl-bytes":"20"},
		{".id":"*8","protocol":"tcp","src-address":"192.168.88.20","src-port":"1000","dst-address":"8.8.8.8","dst-port":"443","reply-src-address":"8.8.8.8","reply-src-port":"443","reply-dst-address":"198.51.100.216","reply-dst-port":"1000","orig-bytes":"1","repl-bytes":"1","tcp-state":"established"}]`,
	"/rest/ip/dns/cache": `[{"name":"router.lan","type":"A","data":"192.168.88.1","ttl":"0s"},
		{"name":"www.example.com","type":"CNAME","data":"edge.example.net.","ttl":"1h"},
		{"name":"edge.example.net","type":"A","data":"203.0.113.80","ttl":"2d12h18m13s"},
		{"name":"v6.example.org","type":"AAAA","data":"2001:db8::1","ttl":"4m32s"}]`,
}

func TestRouterREST(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if r.Method != http.MethodGet || !ok || user != "networker" || password != "secret" || r.URL.Query().Get(".proplist") == "" {
			http.Error(w, `{"error":401}`, http.StatusUnauthorized)
			return
		}
		body, found := sample[r.URL.Path]
		if !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	ctx := context.Background()

	wrong, err := New(server.URL, "networker", "wrong", ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.Refresh(ctx); err == nil {
		t.Fatal("wrong password accepted")
	}

	r, err := New(server.URL, "networker", "secret", ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Connections(ctx, nil); err == nil {
		t.Fatal("connections before topology load")
	}
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	host := netip.MustParseAddr("192.168.10.20")
	connections, err := r.Connections(ctx, func(ip netip.Addr) bool { return ip == host })
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]Connection)
	for _, c := range connections {
		byID[c.ID] = c
	}
	// *2 is this host, *3 goes to the router itself, *5 is ICMP, *6 is the router's own traffic.
	if len(connections) != 4 {
		t.Fatalf("connections: %+v", connections)
	}
	mac := byID["*1"]
	if mac.Device.Name != "laptop" || mac.Device.VLAN != 10 || mac.Device.Interface != "Management" || mac.Device.MAC != "AA:BB:CC:00:00:39" ||
		mac.Local != netip.MustParseAddrPort("192.168.10.21:64356") || mac.Remote != netip.MustParseAddrPort("17.57.146.139:5223") ||
		mac.Inbound || !mac.Established || mac.Sent != 674347 || mac.Received != 1406539 {
		t.Fatalf("outbound: %+v", mac)
	}
	// Port forward: the LAN server answered, so it is the device and counters swap.
	forward := byID["*4"]
	if !forward.Inbound || forward.Device.Name != "Media server" || forward.Device.VLAN != 100 || forward.Local != netip.MustParseAddrPort("10.0.0.50:8443") ||
		forward.Remote != netip.MustParseAddrPort("203.0.113.9:40000") || forward.Sent != 9000 || forward.Received != 100 || forward.Established {
		t.Fatalf("port forward: %+v", forward)
	}
	// Between VLANs, the opener is the device.
	if between := byID["*7"]; between.Device.Name != "Media server" || between.Remote.Addr() != netip.MustParseAddr("192.168.10.21") || between.Inbound {
		t.Fatalf("inter-VLAN: %+v", between)
	}
	// Untagged bridge traffic belongs to the bridge PVID.
	if untagged := byID["*8"]; untagged.Device.VLAN != 1 || untagged.Device.Interface != "bridge" {
		t.Fatalf("bridge PVID: %+v", untagged)
	}
	if d := r.Lookup(netip.MustParseAddr("198.51.100.40")); d != nil {
		t.Fatalf("WAN neighbour described as LAN device: %+v", d)
	}
	if d := r.Lookup(netip.MustParseAddr("192.168.10.1")); d != nil {
		t.Fatalf("router described as LAN device: %+v", d)
	}
	if d := r.Lookup(host); d == nil || d.Name != "desktop" || d.VLAN != 10 {
		t.Fatalf("host lookup: %+v", d)
	}

	answers, err := r.DNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 2 || answers[0].Name != "www.example.com" || answers[0].Address != netip.MustParseAddr("203.0.113.80") || answers[0].TTL != time.Hour ||
		answers[1].Name != "v6.example.org" || answers[1].TTL != 4*time.Minute+32*time.Second {
		t.Fatalf("DNS answers: %+v", answers)
	}
}

func TestNewRejectsUnsafeConfig(t *testing.T) {
	for _, base := range []string{"http://192.168.10.1", "https://user:pw@192.168.10.1", "https://192.168.10.1/rest", "192.168.10.1"} {
		if _, err := New(base, "u", "p", nil); err == nil {
			t.Fatalf("accepted %q", base)
		}
	}
	if _, err := New("https://192.168.10.1", "u", "p", []byte("not a certificate")); err == nil {
		t.Fatal("accepted CA without PEM certificate")
	}
}

func TestDuration(t *testing.T) {
	for text, want := range map[string]time.Duration{
		"0s": 0, "59s": 59 * time.Second, "1w2d3h4m5s": 9*24*time.Hour + 3*time.Hour + 4*time.Minute + 5*time.Second, "250ms": 250 * time.Millisecond,
	} {
		if got, ok := duration(text); !ok || got != want {
			t.Fatalf("%s: %v %v", text, got, ok)
		}
	}
	for _, text := range []string{"s", "5x", "1h-2m"} {
		if _, ok := duration(text); ok {
			t.Fatalf("accepted %q", text)
		}
	}
}
