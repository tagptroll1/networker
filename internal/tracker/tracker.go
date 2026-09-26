package tracker

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/tagptroll1/networker/internal/capture"
	"github.com/tagptroll1/networker/internal/history"
	"github.com/tagptroll1/networker/internal/router"
)

type Source interface {
	Snapshot() ([]capture.Flow, error)
}
type History interface {
	Add(context.Context, history.Connection) (int64, error)
	Update(context.Context, history.Connection) error
}

type Flow struct {
	ID         int64          `json:"id"`
	StartedAt  time.Time      `json:"started_at"`
	LastSeen   time.Time      `json:"last_seen"`
	App        string         `json:"app"`
	PID        uint32         `json:"pid,omitempty"`
	Executable string         `json:"executable,omitempty"`
	Unit       string         `json:"unit,omitempty"`
	Local      netip.AddrPort `json:"local"`
	Remote     netip.AddrPort `json:"remote"`
	Protocol   string         `json:"protocol"`
	Direction  string         `json:"direction"`
	Status     string         `json:"status"`
	Sent       uint64         `json:"sent_bytes"`
	Received   uint64         `json:"received_bytes"`
	// Source is "host" for eBPF-observed sockets, "router" for other LAN devices.
	Source string          `json:"source"`
	Device *history.Device `json:"device,omitempty"`
}

type session struct {
	flow   Flow
	kernel capture.Flow
}

type Tracker struct {
	mu       sync.RWMutex
	source   Source
	history  History
	sessions map[capture.Key]session
	routed   map[string]routedSession
}

type routedSession struct {
	flow           Flow
	sent, received uint64
}

func New(source Source, store History) *Tracker {
	return &Tracker{source: source, history: store, sessions: make(map[capture.Key]session), routed: make(map[string]routedSession)}
}

func (t *Tracker) Poll(ctx context.Context, now time.Time, monoNS uint64) error {
	samples, err := t.source.Snapshot()
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	present := make(map[capture.Key]bool, len(samples))
	for _, sample := range samples {
		if !sample.Ready {
			continue
		}
		present[sample.Key] = true
		prior, found := t.sessions[sample.Key]
		if found && prior.kernel.LastNS == sample.LastNS && prior.kernel.PID == sample.PID && prior.kernel.App == sample.App && prior.kernel.Executable == sample.Executable && prior.kernel.Unit == sample.Unit {
			continue
		}
		// A new socket can reuse same 5-tuple; UDP uses idle-time sessions.
		newSession := !found || (sample.Cookie != 0 && prior.kernel.Cookie != 0 && sample.Cookie != prior.kernel.Cookie) ||
			(sample.LastNS > prior.kernel.LastNS && sample.LastNS-prior.kernel.LastNS > uint64(60*time.Second)) ||
			sample.Sent < prior.kernel.Sent || sample.Received < prior.kernel.Received
		first := now
		if newSession && sample.FirstNS <= monoNS && monoNS-sample.FirstNS < uint64(24*time.Hour) {
			first = now.Add(-time.Duration(monoNS - sample.FirstNS))
		}
		last := now
		if sample.LastNS <= monoNS && monoNS-sample.LastNS < uint64(24*time.Hour) {
			last = now.Add(-time.Duration(monoNS - sample.LastNS))
		}
		app := sample.App
		if app == "" {
			app = "unknown"
		}
		direction := "outbound"
		if sample.Inbound {
			direction = "inbound"
		}
		status := "observed"
		if sample.Established && !sample.Inbound {
			status = "established"
		}
		protocol := "tcp"
		if sample.Key.Protocol == 17 {
			protocol = "udp"
		}
		flow := Flow{StartedAt: first, LastSeen: last, App: app, PID: sample.PID, Executable: sample.Executable, Unit: sample.Unit,
			Local: sample.Key.Local, Remote: sample.Key.Remote, Protocol: protocol,
			Direction: direction, Status: status, Sent: sample.Sent, Received: sample.Received, Source: "host"}
		if found && !newSession {
			flow.ID, flow.StartedAt = prior.flow.ID, prior.flow.StartedAt
			if flow.PID == 0 {
				flow.PID, flow.Executable, flow.Unit = prior.flow.PID, prior.flow.Executable, prior.flow.Unit
				if flow.App == "unknown" {
					flow.App = prior.flow.App
				}
			}
			flow.Sent = prior.flow.Sent + (sample.Sent - prior.kernel.Sent)
			flow.Received = prior.flow.Received + (sample.Received - prior.kernel.Received)
		} else if found && sample.Sent >= prior.kernel.Sent && sample.Received >= prior.kernel.Received {
			// Reused tuples retain kernel counters until map eviction.
			flow.Sent = sample.Sent - prior.kernel.Sent
			flow.Received = sample.Received - prior.kernel.Received
		}
		record := history.Connection{ID: flow.ID, StartedAt: flow.StartedAt, App: flow.App, PID: flow.PID,
			Local: flow.Local.String(), Executable: flow.Executable, Unit: flow.Unit,
			RemoteIP: flow.Remote.Addr(), RemotePort: flow.Remote.Port(), Protocol: protocol,
			Direction: direction, Status: status, Sent: flow.Sent, Received: flow.Received, Source: "host"}
		if newSession {
			// A reused tuple is first seen now, not when previous kernel entry was created.
			if found {
				flow.StartedAt, record.StartedAt = now, now
			}
			id, err := t.history.Add(ctx, record)
			if err != nil {
				return fmt.Errorf("save connection: %w", err)
			}
			flow.ID = id
		} else if err := t.history.Update(ctx, record); err != nil {
			return fmt.Errorf("update connection: %w", err)
		}
		t.sessions[sample.Key] = session{flow, sample}
	}
	for key := range t.sessions {
		if !present[key] {
			delete(t.sessions, key)
		}
	}
	return nil
}

// SyncRouter records other LAN devices' connections from a router snapshot.
// Router counters are cumulative, so a connection counts as active only
// while its counters grow.
func (t *Tracker) SyncRouter(ctx context.Context, now time.Time, connections []router.Connection) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	present := make(map[string]bool, len(connections))
	for _, c := range connections {
		key := fmt.Sprint(c.ID, c.Protocol, c.Local, c.Remote)
		present[key] = true
		prior, found := t.routed[key]
		if found && prior.sent == c.Sent && prior.received == c.Received && prior.flow.Status == routedStatus(c) && *prior.flow.Device == c.Device {
			continue
		}
		direction := "outbound"
		if c.Inbound {
			direction = "inbound"
		}
		device := c.Device
		flow := Flow{StartedAt: now, LastSeen: now, Local: c.Local, Remote: c.Remote, Protocol: c.Protocol,
			Direction: direction, Status: routedStatus(c), Sent: c.Sent, Received: c.Received, Source: "router", Device: &device}
		if found && c.Sent >= prior.sent && c.Received >= prior.received {
			flow.ID, flow.StartedAt = prior.flow.ID, prior.flow.StartedAt
			if c.Sent == prior.sent && c.Received == prior.received {
				flow.LastSeen = prior.flow.LastSeen
			}
		}
		record := history.Connection{ID: flow.ID, StartedAt: flow.StartedAt, Local: flow.Local.String(),
			RemoteIP: flow.Remote.Addr(), RemotePort: flow.Remote.Port(), Protocol: flow.Protocol, Direction: direction,
			Status: flow.Status, Sent: flow.Sent, Received: flow.Received, Source: "router", Device: &device}
		if flow.ID == 0 {
			id, err := t.history.Add(ctx, record)
			if err != nil {
				return fmt.Errorf("save router connection: %w", err)
			}
			flow.ID = id
		} else if err := t.history.Update(ctx, record); err != nil {
			return fmt.Errorf("update router connection: %w", err)
		}
		t.routed[key] = routedSession{flow, c.Sent, c.Received}
	}
	for key := range t.routed {
		if !present[key] {
			delete(t.routed, key)
		}
	}
	return nil
}

func routedStatus(c router.Connection) string {
	if c.Established {
		return "established"
	}
	return "observed"
}

func (t *Tracker) Live(now time.Time) []Flow {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]Flow, 0)
	for _, s := range t.sessions {
		if now.Sub(s.flow.LastSeen) < 30*time.Second {
			result = append(result, s.flow)
		}
	}
	for _, s := range t.routed {
		if now.Sub(s.flow.LastSeen) < 30*time.Second {
			result = append(result, s.flow)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LastSeen.After(result[j].LastSeen) })
	return result
}
