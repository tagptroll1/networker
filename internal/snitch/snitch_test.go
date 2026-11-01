package snitch

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tagptroll1/networker/internal/capture"
	"github.com/tagptroll1/networker/internal/tracker"
)

type fakeEnforcer struct {
	on       bool
	assigned map[uint32]uint32
	blocked  map[string]bool
}

func newFakeEnforcer() *fakeEnforcer {
	return &fakeEnforcer{assigned: make(map[uint32]uint32), blocked: make(map[string]bool)}
}
func (f *fakeEnforcer) SetEnforcing(on bool) error { f.on = on; return nil }
func (f *fakeEnforcer) AssignApp(pid, app uint32) error {
	f.assigned[pid] = app
	return nil
}
func (f *fakeEnforcer) Block(app uint32, prefix netip.Prefix) error {
	f.blocked[fmt.Sprint(app, " ", prefix)] = true
	return nil
}
func (f *fakeEnforcer) Unblock(app uint32, prefix netip.Prefix) error {
	delete(f.blocked, fmt.Sprint(app, " ", prefix))
	return nil
}

func TestParseRules(t *testing.T) {
	rules, err := ParseRules([]byte(`[{"app":"a","host":"Example.COM."},{"app":"*","cidr":"10.0.0.1"}]`))
	if err != nil || rules[0].Host != "example.com" {
		t.Fatalf("rules %+v, err %v", rules, err)
	}
	for _, bad := range []string{
		`[{"host":"a.com"}]`,
		`[{"app":"a"}]`,
		`[{"app":"a","host":"a.com","cidr":"1.2.3.4"}]`,
		`[{"app":"a","host":"*.a.com"}]`,
		`[{"app":"a","cidr":"nope"}]`,
		`[{"app":"a","hots":"a.com"}]`,
		`not json`,
	} {
		if _, err := ParseRules([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestPolicyEnforces(t *testing.T) {
	enforcer := newFakeEnforcer()
	identify := map[uint32]string{1: "freetube", 2: "other"}
	rules := []Rule{{App: "freetube", Host: "gvt1.com"}, {App: Everyone, CIDR: "10.0.0.0/8"}, {App: "freetube", CIDR: "2001:db8::1"}}
	p := NewPolicy(rules, enforcer, func(pid uint32) string { return identify[pid] })
	if err := p.Start([]uint32{1, 2}); err != nil {
		t.Fatal(err)
	}
	if !enforcer.on {
		t.Error("checks not armed")
	}
	if !reflect.DeepEqual(enforcer.assigned, map[uint32]uint32{1: 1}) {
		t.Errorf("assigned %v: only ruled apps need an entry", enforcer.assigned)
	}
	if !enforcer.blocked["0 10.0.0.0/8"] || !enforcer.blocked["1 2001:db8::1/128"] {
		t.Errorf("address rules missing: %v", enforcer.blocked)
	}
	now := time.Now()
	p.Answers([]capture.DNSAnswer{
		{Name: "rr1.gvt1.com", Address: netip.MustParseAddr("1.2.3.4"), TTL: time.Minute},
		{Name: "notgvt1.com", Address: netip.MustParseAddr("5.6.7.8"), TTL: time.Minute},
	}, now)
	if !enforcer.blocked["1 1.2.3.4/32"] || enforcer.blocked["1 5.6.7.8/32"] {
		t.Errorf("learned addresses: %v", enforcer.blocked)
	}
	// Held past the TTL, since clients cache longer than DNS says.
	p.Sweep(now.Add(30 * time.Minute))
	if !enforcer.blocked["1 1.2.3.4/32"] {
		t.Error("released before the hold ran out")
	}
	p.Sweep(now.Add(2 * time.Hour))
	if enforcer.blocked["1 1.2.3.4/32"] {
		t.Error("never released")
	}
	if !enforcer.blocked["0 10.0.0.0/8"] {
		t.Error("swept a configured rule")
	}
}

func TestPolicyMatch(t *testing.T) {
	p := NewPolicy([]Rule{{App: "a", Host: "gvt1.com"}, {App: Everyone, CIDR: "10.0.0.0/8"}}, nil, nil)
	ip := netip.MustParseAddr("1.1.1.1")
	for _, c := range []struct {
		app, host string
		ip        netip.Addr
		match     bool
	}{
		{"a", "gvt1.com", ip, true},
		{"a", "x.gvt1.com", ip, true},
		{"a", "notgvt1.com", ip, false},
		{"b", "gvt1.com", ip, false},
		{"b", "", netip.MustParseAddr("10.1.2.3"), true},
		{"b", "", netip.MustParseAddr("::ffff:10.1.2.3"), true},
	} {
		if got := p.Match(c.app, c.host, c.ip) != ""; got != c.match {
			t.Errorf("%+v: got %v", c, got)
		}
	}
	if p.Enforcing() {
		t.Error("nil enforcer must be a dry run")
	}
	// A dry run touches no kernel state.
	if err := p.Start([]uint32{1}); err != nil {
		t.Fatal(err)
	}
	p.Exec(1)
	p.Answers([]capture.DNSAnswer{{Name: "gvt1.com", Address: ip, TTL: time.Minute}}, time.Now())
	p.Sweep(time.Now())
}

func flow(id int64, app string, remote string, sent, received uint64) tracker.Flow {
	return tracker.Flow{ID: id, App: app, Source: "host", Direction: "outbound", Protocol: "tcp",
		Remote: netip.MustParseAddrPort(remote), Sent: sent, Received: received}
}

func open(t *testing.T, options Options) *Monitor {
	t.Helper()
	if options.Path == "" {
		options.Path = filepath.Join(t.TempDir(), "snitch.db")
	}
	if options.Retention == 0 {
		options.Retention = time.Hour * 24 * 90
	}
	if options.MaxDestinations == 0 {
		options.MaxDestinations = 100
	}
	m, err := Open(options, NewPolicy(nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func TestObserveCountsDeltas(t *testing.T) {
	m := open(t, Options{})
	now := time.Now()
	m.Observe(now, []Seen{{flow(1, "a", "1.1.1.1:443", 100, 10), "x.com"}})
	m.Observe(now.Add(time.Second), []Seen{{flow(1, "a", "1.1.1.1:443", 150, 30), "x.com"}})
	m.Observe(now.Add(2*time.Second), []Seen{{flow(2, "a", "1.1.1.1:443", 5, 5), "x.com"}})
	got := m.Destinations("a")
	if len(got) != 1 || got[0].Sent != 155 || got[0].Received != 35 || got[0].Connections != 2 {
		t.Fatalf("%+v", got)
	}
	// Dropping out of the live view and returning is not a new connection.
	m.Observe(now.Add(3*time.Second), nil)
	m.Observe(now.Add(4*time.Second), []Seen{{flow(2, "a", "1.1.1.1:443", 6, 5), "x.com"}})
	got = m.Destinations("a")
	if got[0].Sent != 156 || got[0].Connections != 2 {
		t.Fatalf("after return: %+v", got)
	}
}

func TestObserveIgnoresWhatAnAppDidNotSend(t *testing.T) {
	m := open(t, Options{})
	inbound := flow(1, "a", "1.1.1.1:443", 1, 1)
	inbound.Direction = "inbound"
	routed := flow(2, "a", "1.1.1.1:443", 1, 1)
	routed.Source = "router"
	m.Observe(time.Now(), []Seen{{inbound, ""}, {routed, ""}, {flow(3, "a", "127.0.0.1:80", 1, 1), ""},
		{flow(4, "a", "224.0.0.251:5353", 1, 1), ""}, {flow(5, "a", "[fe80::1]:80", 1, 1), ""}})
	if apps := m.Apps(); len(apps) != 0 {
		t.Fatalf("%+v", apps)
	}
}

func TestAddressMovesToDomain(t *testing.T) {
	m := open(t, Options{})
	now := time.Now()
	m.Observe(now, []Seen{{flow(1, "a", "1.1.1.1:443", 10, 0), ""}})
	m.Observe(now.Add(time.Second), []Seen{{flow(1, "a", "1.1.1.1:443", 15, 0), "x.com"}})
	m.Observe(now.Add(2*time.Second), []Seen{{flow(1, "a", "1.1.1.1:443", 16, 0), ""}})
	hosts := map[string]uint64{}
	for _, d := range m.Destinations("a") {
		hosts[d.Host] = d.Sent
	}
	if !reflect.DeepEqual(hosts, map[string]uint64{"1.1.1.1": 10, "x.com": 6}) {
		t.Fatalf("%v", hosts)
	}
}

func TestAlerts(t *testing.T) {
	m := open(t, Options{Learn: time.Hour, Watch: []string{"watched"}, Quiet: []string{"quiet", "both"}})
	start := time.Now()
	seen := func(at time.Time, id int64, app, host string) {
		m.Observe(at, []Seen{{flow(id, app, "1.1.1.1:443", 1, 1), host}})
	}
	seen(start, 1, "a", "first.com")
	seen(start, 2, "watched", "w.com")
	seen(start, 3, "quiet", "q.com")
	seq, alerts := m.Alerts(0)
	if seq != 1 || len(alerts) != 1 || alerts[0].App != "watched" {
		t.Fatalf("while learning: %d %+v", seq, alerts)
	}
	seen(start.Add(30*time.Minute), 4, "a", "still-learning.com")
	if seq, _ = m.Alerts(0); seq != 1 {
		t.Fatalf("alerted during learning: %d", seq)
	}
	later := start.Add(2 * time.Hour)
	seen(later, 5, "a", "new.com")
	seen(later, 6, "a", "new.com") // already known
	seen(later, 7, "quiet", "new.com")
	m.Blocked(later, "a", "", netip.MustParseAddr("9.9.9.9"))
	seq, alerts = m.Alerts(1)
	if seq != 3 || len(alerts) != 2 || alerts[0].Host != "new.com" || alerts[1].Host != "9.9.9.9" || !alerts[1].Blocked {
		t.Fatalf("after learning: %d %+v", seq, alerts)
	}
	if _, alerts = m.Alerts(3); len(alerts) != 0 {
		t.Fatalf("nothing newer: %+v", alerts)
	}
}

func TestPersistsAndPrunes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snitch.db")
	options := Options{Path: path, Learn: time.Hour, Retention: 24 * time.Hour, MaxDestinations: 2}
	first, err := Open(options, NewPolicy(nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	first.Observe(now, []Seen{{flow(1, "a", "1.1.1.1:443", 7, 3), "x.com"}})
	first.Blocked(now, "a", "y.com", netip.MustParseAddr("2.2.2.2"))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(options, NewPolicy([]Rule{{App: "a", Host: "y.com"}}, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	got := second.Destinations("a")
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	byHost := map[string]Destination{got[0].Host: got[0], got[1].Host: got[1]}
	if byHost["x.com"].Sent != 7 || byHost["y.com"].Blocked != 1 || byHost["y.com"].Rule == "" || byHost["x.com"].Rule != "" {
		t.Fatalf("%+v", byHost)
	}
	// The app is known from the record, so its learning period is not restarted.
	second.Observe(now.Add(2*time.Hour), []Seen{{flow(2, "a", "3.3.3.3:443", 1, 1), "z.com"}})
	if seq, _ := second.Alerts(0); seq != 1 {
		t.Fatalf("learning restarted: %d", seq)
	}
	if err := second.Tick(context.Background(), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := second.Destinations("a"); len(got) != 2 || got[0].Host != "z.com" {
		t.Fatalf("over the cap: %+v", got)
	}
	if err := second.Tick(context.Background(), now.Add(100*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if apps := second.Apps(); len(apps) != 0 {
		t.Fatalf("past retention: %+v", apps)
	}
}
