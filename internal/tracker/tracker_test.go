package tracker

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagptroll1/networker/internal/capture"
	"github.com/tagptroll1/networker/internal/history"
	"github.com/tagptroll1/networker/internal/router"
)

type source struct{ flows []capture.Flow }

func (s *source) Snapshot() ([]capture.Flow, error) { return s.flows, nil }

func TestUDPHistorySessions(t *testing.T) {
	db, err := history.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src := &source{}
	tracked := New(src, db)
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	mono := uint64(100 * time.Second)
	key := capture.Key{Local: netip.MustParseAddrPort("192.168.1.10:1234"), Remote: netip.MustParseAddrPort("1.1.1.1:53"), Protocol: 17}
	src.flows = []capture.Flow{{Key: key, FirstNS: mono, LastNS: mono, Sent: 70, Ready: true, Cookie: 1, App: "spotify"}}
	poll := func() {
		t.Helper()
		if err := tracked.Poll(context.Background(), now, mono); err != nil {
			t.Fatal(err)
		}
	}
	poll()
	if got := tracked.Live(now); len(got) != 1 || got[0].App != "spotify" {
		t.Fatalf("live: %+v", got)
	}
	now, mono = now.Add(time.Second), mono+uint64(time.Second)
	src.flows[0].LastNS, src.flows[0].Sent, src.flows[0].Received = mono, 100, 200
	poll()
	now, mono = now.Add(61*time.Second), mono+uint64(61*time.Second)
	src.flows[0].LastNS, src.flows[0].Sent = mono, 150
	poll()
	records, err := db.List(context.Background(), time.Unix(0, 0), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Sent != 50 || records[1].Sent != 100 || records[1].Received != 200 {
		t.Fatalf("sessions: %+v", records)
	}
}

func TestTCPReadiness(t *testing.T) {
	db, err := history.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src := &source{flows: []capture.Flow{{Key: capture.Key{Local: netip.MustParseAddrPort("[::1]:2000"),
		Remote: netip.MustParseAddrPort("[2606:4700:4700::1111]:443"), Protocol: 6}, FirstNS: 1, LastNS: 1, Sent: 40}}}
	tracked := New(src, db)
	now := time.Now()
	if err := tracked.Poll(context.Background(), now, 1); err != nil {
		t.Fatal(err)
	}
	if len(tracked.Live(now)) != 0 {
		t.Fatal("outgoing SYN alone is not a connection")
	}
	src.flows[0].Ready, src.flows[0].Established, src.flows[0].LastNS, src.flows[0].Cookie = true, true, 2, 1
	if err := tracked.Poll(context.Background(), now, 2); err != nil {
		t.Fatal(err)
	}
	live := tracked.Live(now)
	if len(live) != 1 || live[0].Status != "established" || live[0].App != "unknown" {
		t.Fatalf("ready: %+v", live)
	}
	src.flows[0].Cookie, src.flows[0].Sent, src.flows[0].LastNS = 2, 30, 3
	src.flows[0].Established = false
	if err := tracked.Poll(context.Background(), now.Add(time.Second), 3); err != nil {
		t.Fatal(err)
	}
	records, err := db.List(context.Background(), time.Unix(0, 0), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Status != "observed" || records[0].Sent != 30 {
		t.Fatalf("reused TCP tuple: %+v", records)
	}
}

func TestLateAttributionPreserved(t *testing.T) {
	db, err := history.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := capture.Key{Local: netip.MustParseAddrPort("127.0.0.1:13420"), Remote: netip.MustParseAddrPort("127.0.0.1:49153"), Protocol: 6}
	src := &source{flows: []capture.Flow{{Key: key, Cookie: 1, Ready: true, FirstNS: 1, LastNS: 1, Received: 100, Inbound: true}}}
	tracked := New(src, db)
	now := time.Now()
	if err := tracked.Poll(context.Background(), now, 1); err != nil {
		t.Fatal(err)
	}
	src.flows[0].PID, src.flows[0].App, src.flows[0].Executable, src.flows[0].Unit = 123, "server", "/usr/bin/server", "server.service"
	if err := tracked.Poll(context.Background(), now, 1); err != nil {
		t.Fatal(err)
	}
	if got := tracked.Live(now); len(got) != 1 || got[0].PID != 123 || got[0].Local != key.Local || got[0].Unit != "server.service" {
		t.Fatalf("late attribution: %+v", got)
	}
	src.flows[0].PID, src.flows[0].App, src.flows[0].Executable, src.flows[0].Unit = 0, "", "", ""
	src.flows[0].LastNS++
	if err := tracked.Poll(context.Background(), now, 2); err != nil {
		t.Fatal(err)
	}
	records, err := db.List(context.Background(), time.Unix(0, 0), 10)
	if err != nil || len(records) != 1 || records[0].PID != 123 || records[0].Local != key.Local.String() || records[0].Executable != "/usr/bin/server" {
		t.Fatalf("history: %+v, %v", records, err)
	}
}

func TestRouterSessions(t *testing.T) {
	db, err := history.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tracked := New(nil, db)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	c := router.Connection{ID: "*1", Protocol: "tcp", Local: netip.MustParseAddrPort("192.168.10.21:5000"), Remote: netip.MustParseAddrPort("17.57.146.139:5223"),
		Device: history.Device{IP: netip.MustParseAddr("192.168.10.21"), Name: "laptop", VLAN: 10, Interface: "Management"}, Established: true, Sent: 100, Received: 200}
	sync := func(connections ...router.Connection) {
		t.Helper()
		if err := tracked.SyncRouter(context.Background(), now, connections); err != nil {
			t.Fatal(err)
		}
	}
	sync(c)
	live := tracked.Live(now)
	if len(live) != 1 || live[0].Source != "router" || live[0].Device.VLAN != 10 || live[0].Status != "established" || live[0].Sent != 100 {
		t.Fatalf("live: %+v", live)
	}
	first := live[0].ID
	// Idle connections fall out of the live view but keep their row.
	now = now.Add(40 * time.Second)
	sync(c)
	if got := tracked.Live(now); len(got) != 0 {
		t.Fatalf("idle connection still live: %+v", got)
	}
	now = now.Add(5 * time.Second)
	c.Received = 900
	sync(c)
	if got := tracked.Live(now); len(got) != 1 || got[0].ID != first || got[0].Received != 900 || !got[0].StartedAt.Equal(now.Add(-45*time.Second)) {
		t.Fatalf("growing connection: %+v", got)
	}
	sync()
	if got := tracked.Live(now); len(got) != 0 {
		t.Fatalf("closed connection still live: %+v", got)
	}
	records, err := db.List(context.Background(), time.Unix(0, 0), 10)
	if err != nil || len(records) != 1 || records[0].Source != "router" || records[0].Received != 900 || records[0].Device == nil ||
		records[0].Device.Name != "laptop" || records[0].Device.VLAN != 10 || records[0].Local != "192.168.10.21:5000" {
		t.Fatalf("history: %+v %v", records, err)
	}
}
