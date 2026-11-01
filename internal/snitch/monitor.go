package snitch

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/tagptroll1/networker/internal/tracker"
)

const (
	flushEvery = 30 * time.Second
	pruneEvery = time.Hour
	maxAlerts  = 256
)

// Options configures what is remembered and what deserves an alert.
type Options struct {
	Path string
	// Learn is how long after an app first appears its new destinations are
	// expected, and so raise no alert.
	Learn time.Duration
	// Watch skips learning for these apps; Quiet never alerts for these.
	Watch, Quiet    []string
	Retention       time.Duration
	MaxDestinations int
}

// Destination is everywhere one app has been seen talking to one host.
type Destination struct {
	App         string     `json:"app"`
	Host        string     `json:"host"`
	IP          netip.Addr `json:"ip"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	Sent        uint64     `json:"sent_bytes"`
	Received    uint64     `json:"received_bytes"`
	Connections uint64     `json:"connections"`
	Blocked     uint64     `json:"blocked"`
	// Rule covers this destination; it is refused only when enforcing.
	Rule string `json:"rule,omitempty"`
}

// App summarises one app's destinations.
type App struct {
	App          string    `json:"app"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Destinations int       `json:"destinations"`
	Sent         uint64    `json:"sent_bytes"`
	Received     uint64    `json:"received_bytes"`
	Blocked      uint64    `json:"blocked"`
}

// Alert announces a destination not seen before.
type Alert struct {
	Seq     uint64    `json:"seq"`
	At      time.Time `json:"at"`
	App     string    `json:"app"`
	Host    string    `json:"host"`
	Blocked bool      `json:"blocked"`
}

type destinationKey struct{ app, host string }

type counters struct {
	key            destinationKey
	sent, received uint64
}

// Seen is a live flow with its destination name, when known.
type Seen struct {
	tracker.Flow
	Host string
}

// Monitor keeps destinations in memory and writes them out periodically, so
// one streaming app does not mean one database write a second.
type Monitor struct {
	options Options
	policy  *Policy
	db      *sql.DB

	mu           sync.RWMutex
	destinations map[destinationKey]*Destination
	dirty        map[destinationKey]bool
	appFirstSeen map[string]time.Time
	flows        map[int64]counters
	alerts       []Alert
	seq          uint64
	flushed      time.Time
	pruned       time.Time
}

// Open loads what earlier runs recorded.
func Open(options Options, policy *Policy) (*Monitor, error) {
	if err := os.MkdirAll(filepath.Dir(options.Path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(options.Path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", options.Path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`PRAGMA busy_timeout=5000`,
		`PRAGMA journal_mode=WAL`,
		`CREATE TABLE IF NOT EXISTS destinations (
			app TEXT NOT NULL,
			host TEXT NOT NULL,
			ip TEXT NOT NULL,
			first_seen INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			sent_bytes INTEGER NOT NULL,
			received_bytes INTEGER NOT NULL,
			connections INTEGER NOT NULL,
			blocked INTEGER NOT NULL,
			PRIMARY KEY (app, host)
		)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("initialize snitch: %w", err)
		}
	}
	m := &Monitor{options: options, policy: policy, db: db, destinations: make(map[destinationKey]*Destination),
		dirty: make(map[destinationKey]bool), appFirstSeen: make(map[string]time.Time), flows: make(map[int64]counters)}
	if err := m.load(); err != nil {
		db.Close()
		return nil, err
	}
	return m, nil
}

func (m *Monitor) load() error {
	rows, err := m.db.Query(`SELECT app, host, ip, first_seen, last_seen, sent_bytes, received_bytes, connections, blocked FROM destinations`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d Destination
		var ip string
		var first, last int64
		if err := rows.Scan(&d.App, &d.Host, &ip, &first, &last, &d.Sent, &d.Received, &d.Connections, &d.Blocked); err != nil {
			return err
		}
		d.IP, _ = netip.ParseAddr(ip)
		d.FirstSeen, d.LastSeen = time.Unix(0, first), time.Unix(0, last)
		m.destinations[destinationKey{d.App, d.Host}] = &d
		m.noteApp(d.App, d.FirstSeen)
	}
	return rows.Err()
}

func (m *Monitor) noteApp(app string, at time.Time) {
	if first, ok := m.appFirstSeen[app]; !ok || at.Before(first) {
		m.appFirstSeen[app] = at
	}
}

// Observe folds a poll's live flows into the record. Only this host's outbound
// traffic counts: it is what an app chose to send.
func (m *Monitor) Observe(now time.Time, flows []Seen) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := make(map[int64]counters, len(flows))
	for _, flow := range flows {
		ip := flow.Remote.Addr().Unmap()
		if flow.Source != "host" || flow.Direction != "outbound" || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}
		prior, known := m.flows[flow.ID]
		key := prior.key
		// A flow first seen by address moves over once DNS names it.
		if !known || flow.Host != "" {
			key = destinationKey{flow.App, destinationName(flow.Host, ip)}
		}
		d := m.destination(now, key, ip, false)
		d.IP = ip
		d.LastSeen = now
		if !known {
			d.Connections++
		}
		sent, received := flow.Sent, flow.Received
		if known && sent >= prior.sent && received >= prior.received {
			sent, received = sent-prior.sent, received-prior.received
		}
		d.Sent += sent
		d.Received += received
		m.dirty[key] = true
		current[flow.ID] = counters{key, flow.Sent, flow.Received}
	}
	// Flows age out of the live view; keep them so one reappearing is not recounted.
	for id, item := range m.flows {
		if _, ok := current[id]; !ok && len(m.flows) < 65536 {
			current[id] = item
		}
	}
	m.flows = current
}

// Blocked records a connection the kernel refused.
func (m *Monitor) Blocked(now time.Time, app, host string, ip netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := destinationKey{app, destinationName(host, ip)}
	d := m.destination(now, key, ip, true)
	d.IP = ip
	d.LastSeen = now
	d.Blocked++
	m.dirty[key] = true
}

func destinationName(host string, ip netip.Addr) string {
	if host != "" {
		return host
	}
	return ip.String()
}

func (m *Monitor) destination(now time.Time, key destinationKey, ip netip.Addr, blocked bool) *Destination {
	if d := m.destinations[key]; d != nil {
		return d
	}
	if m.shouldAlert(now, key.app) {
		m.seq++
		m.alerts = append(m.alerts, Alert{m.seq, now, key.app, key.host, blocked})
		if len(m.alerts) > maxAlerts {
			m.alerts = m.alerts[len(m.alerts)-maxAlerts:]
		}
	}
	m.noteApp(key.app, now)
	d := &Destination{App: key.app, Host: key.host, IP: ip, FirstSeen: now, LastSeen: now}
	m.destinations[key] = d
	return d
}

func (m *Monitor) shouldAlert(now time.Time, app string) bool {
	if slices.Contains(m.options.Quiet, app) {
		return false
	}
	if slices.Contains(m.options.Watch, app) {
		return true
	}
	first, known := m.appFirstSeen[app]
	return known && now.Sub(first) >= m.options.Learn
}

// Tick saves and prunes when due. Call it regularly.
func (m *Monitor) Tick(ctx context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.Sub(m.pruned) >= pruneEvery {
		m.prune(now)
		m.pruned = now
	}
	if now.Sub(m.flushed) < flushEvery {
		return nil
	}
	m.flushed = now
	return m.flush(ctx)
}

func (m *Monitor) flush(ctx context.Context) error {
	if len(m.dirty) == 0 {
		return nil
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key := range m.dirty {
		d := m.destinations[key]
		if d == nil {
			if _, err := tx.ExecContext(ctx, `DELETE FROM destinations WHERE app=? AND host=?`, key.app, key.host); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO destinations
			(app, host, ip, first_seen, last_seen, sent_bytes, received_bytes, connections, blocked)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, d.App, d.Host, d.IP.String(), d.FirstSeen.UnixNano(), d.LastSeen.UnixNano(),
			d.Sent, d.Received, d.Connections, d.Blocked); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	clear(m.dirty)
	return nil
}

func (m *Monitor) prune(now time.Time) {
	cutoff := now.Add(-m.options.Retention)
	all := make([]*Destination, 0, len(m.destinations))
	for key, d := range m.destinations {
		if d.LastSeen.Before(cutoff) {
			delete(m.destinations, key)
			m.dirty[key] = true
		} else {
			all = append(all, d)
		}
	}
	if extra := len(all) - m.options.MaxDestinations; extra > 0 {
		sort.Slice(all, func(i, j int) bool { return all[i].LastSeen.Before(all[j].LastSeen) })
		for _, d := range all[:extra] {
			key := destinationKey{d.App, d.Host}
			delete(m.destinations, key)
			m.dirty[key] = true
		}
	}
}

// Close saves what is pending.
func (m *Monitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.flush(context.Background())
	if closeErr := m.db.Close(); err == nil {
		err = closeErr
	}
	return err
}

// Apps lists apps, most recently active first.
func (m *Monitor) Apps() []App {
	m.mu.RLock()
	defer m.mu.RUnlock()
	apps := make(map[string]*App)
	for _, d := range m.destinations {
		app := apps[d.App]
		if app == nil {
			app = &App{App: d.App, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen}
			apps[d.App] = app
		}
		if d.FirstSeen.Before(app.FirstSeen) {
			app.FirstSeen = d.FirstSeen
		}
		if d.LastSeen.After(app.LastSeen) {
			app.LastSeen = d.LastSeen
		}
		app.Destinations++
		app.Sent += d.Sent
		app.Received += d.Received
		app.Blocked += d.Blocked
	}
	result := make([]App, 0, len(apps))
	for _, app := range apps {
		result = append(result, *app)
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].LastSeen.After(result[j].LastSeen)
		}
		return result[i].App < result[j].App
	})
	return result
}

// Destinations lists one app's destinations, most recently active first.
func (m *Monitor) Destinations(app string) []Destination {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Destination, 0)
	for _, d := range m.destinations {
		if d.App == app {
			item := *d
			item.Rule = m.policy.Match(d.App, d.Host, d.IP)
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].LastSeen.After(result[j].LastSeen)
		}
		return result[i].Host < result[j].Host
	})
	return result
}

// Alerts returns alerts newer than after, and the newest sequence number.
// The number restarts with the service, so a client ahead of it starts over.
func (m *Monitor) Alerts(after uint64) (uint64, []Alert) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Alert, 0)
	for _, alert := range m.alerts {
		if alert.Seq > after {
			result = append(result, alert)
		}
	}
	return m.seq, result
}

// Status describes the active policy.
func (m *Monitor) Status() (enforcing bool, rules []Rule) {
	return m.policy.Enforcing(), m.policy.Rules()
}
