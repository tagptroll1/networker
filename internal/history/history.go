package history

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

type Connection struct {
	ID         int64      `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	App        string     `json:"app"`
	PID        uint32     `json:"pid,omitempty"`
	Local      string     `json:"local,omitempty"`
	Executable string     `json:"executable,omitempty"`
	Unit       string     `json:"unit,omitempty"`
	RemoteIP   netip.Addr `json:"remote_ip"`
	RemotePort uint16     `json:"remote_port"`
	Protocol   string     `json:"protocol"`
	Direction  string     `json:"direction"`
	Status     string     `json:"status"`
	Sent       uint64     `json:"sent_bytes"`
	Received   uint64     `json:"received_bytes"`
	// Source is "host" for eBPF-observed sockets, "router" for other LAN devices.
	Source string  `json:"source"`
	Device *Device `json:"device,omitempty"`
}

// Device is a LAN client as known by the router.
type Device struct {
	IP        netip.Addr `json:"ip"`
	MAC       string     `json:"mac,omitempty"`
	Name      string     `json:"name,omitempty"`
	VLAN      uint16     `json:"vlan,omitempty"`
	Interface string     `json:"interface,omitempty"`
	// Label and VLANName are the user's own names, added when shown, not stored per row.
	Label    string `json:"label,omitempty"`
	VLANName string `json:"vlan_name,omitempty"`
}

type DNSQuery struct {
	ID        int64      `json:"id"`
	QueriedAt time.Time  `json:"queried_at"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	ServerIP  netip.Addr `json:"server_ip"`
}

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`PRAGMA busy_timeout=5000`,
		`PRAGMA journal_mode=WAL`,
		`CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY,
            started_at INTEGER NOT NULL,
            app TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            remote_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            direction TEXT NOT NULL,
            status TEXT NOT NULL,
            sent_bytes INTEGER NOT NULL,
            received_bytes INTEGER NOT NULL
			, pid INTEGER NOT NULL DEFAULT 0
			, local TEXT NOT NULL DEFAULT ''
			, executable TEXT NOT NULL DEFAULT ''
			, unit TEXT NOT NULL DEFAULT ''
			, source TEXT NOT NULL DEFAULT 'host'
			, device_ip TEXT NOT NULL DEFAULT ''
			, device_mac TEXT NOT NULL DEFAULT ''
			, device_name TEXT NOT NULL DEFAULT ''
			, vlan INTEGER NOT NULL DEFAULT 0
			, interface TEXT NOT NULL DEFAULT ''
        )`,
		`CREATE INDEX IF NOT EXISTS connections_started_at ON connections(started_at DESC, id DESC)`,
		`CREATE TABLE IF NOT EXISTS dns_queries (
			id INTEGER PRIMARY KEY,
			queried_at INTEGER NOT NULL,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			server_ip TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS dns_queries_queried_at ON dns_queries(queried_at DESC, id DESC)`,
		`CREATE TABLE IF NOT EXISTS labels (
			kind TEXT NOT NULL CHECK (kind IN ('vlan', 'ip')),
			key TEXT NOT NULL,
			name TEXT NOT NULL,
			PRIMARY KEY (kind, key)
		)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("initialize history: %w", err)
		}
	}
	// Existing databases keep their history while gaining attribution columns.
	rows, err := db.Query(`PRAGMA table_info(connections)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var id, notNull, primaryKey int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&id, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			db.Close()
			return nil, err
		}
		columns[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, column := range []struct{ name, definition string }{
		{"pid", "INTEGER NOT NULL DEFAULT 0"},
		{"local", "TEXT NOT NULL DEFAULT ''"},
		{"executable", "TEXT NOT NULL DEFAULT ''"},
		{"unit", "TEXT NOT NULL DEFAULT ''"},
		{"source", "TEXT NOT NULL DEFAULT 'host'"},
		{"device_ip", "TEXT NOT NULL DEFAULT ''"},
		{"device_mac", "TEXT NOT NULL DEFAULT ''"},
		{"device_name", "TEXT NOT NULL DEFAULT ''"},
		{"vlan", "INTEGER NOT NULL DEFAULT 0"},
		{"interface", "TEXT NOT NULL DEFAULT ''"},
	} {
		if !columns[column.name] {
			if _, err := db.Exec("ALTER TABLE connections ADD COLUMN " + column.name + " " + column.definition); err != nil {
				db.Close()
				return nil, fmt.Errorf("migrate history: %w", err)
			}
		}
	}
	return &Store{db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Add(ctx context.Context, c Connection) (int64, error) {
	source := c.Source
	if source == "" {
		source = "host"
	}
	var d Device
	deviceIP := ""
	if c.Device != nil {
		d, deviceIP = *c.Device, c.Device.IP.String()
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO connections
		(started_at, app, remote_ip, remote_port, protocol, direction, status, sent_bytes, received_bytes, pid, local, executable, unit,
		source, device_ip, device_mac, device_name, vlan, interface)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, c.StartedAt.UnixNano(), c.App,
		c.RemoteIP.String(), c.RemotePort, c.Protocol, c.Direction, c.Status, c.Sent, c.Received, c.PID, c.Local, c.Executable, c.Unit,
		source, deviceIP, d.MAC, d.Name, d.VLAN, d.Interface)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) Update(ctx context.Context, c Connection) error {
	_, err := s.db.ExecContext(ctx, `UPDATE connections SET app=?, status=?, sent_bytes=?, received_bytes=?, pid=?, local=?, executable=?, unit=? WHERE id=?`,
		c.App, c.Status, c.Sent, c.Received, c.PID, c.Local, c.Executable, c.Unit, c.ID)
	return err
}

func (s *Store) List(ctx context.Context, since time.Time, limit int) ([]Connection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, started_at, app, remote_ip, remote_port,
		protocol, direction, status, sent_bytes, received_bytes, pid, local, executable, unit,
		source, device_ip, device_mac, device_name, vlan, interface FROM connections
        WHERE started_at >= ? ORDER BY started_at DESC, id DESC LIMIT ?`, since.UnixNano(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	connections := make([]Connection, 0)
	for rows.Next() {
		var c Connection
		var d Device
		var stamp int64
		var ip, deviceIP string
		if err := rows.Scan(&c.ID, &stamp, &c.App, &ip, &c.RemotePort, &c.Protocol, &c.Direction, &c.Status, &c.Sent, &c.Received, &c.PID, &c.Local, &c.Executable, &c.Unit,
			&c.Source, &deviceIP, &d.MAC, &d.Name, &d.VLAN, &d.Interface); err != nil {
			return nil, err
		}
		c.StartedAt = time.Unix(0, stamp).UTC()
		if c.RemoteIP, err = netip.ParseAddr(ip); err != nil {
			return nil, err
		}
		if deviceIP != "" {
			if d.IP, err = netip.ParseAddr(deviceIP); err != nil {
				return nil, err
			}
			c.Device = &d
		}
		connections = append(connections, c)
	}
	return connections, rows.Err()
}

// Labels are the user's own names for VLANs and IP addresses. They are not
// pruned, and apply to history too since they are joined in when shown.
type Labels struct {
	VLANs map[uint16]string     `json:"vlans"`
	IPs   map[netip.Addr]string `json:"ips"`
}

func (s *Store) Labels(ctx context.Context) (Labels, error) {
	labels := Labels{VLANs: make(map[uint16]string), IPs: make(map[netip.Addr]string)}
	rows, err := s.db.QueryContext(ctx, `SELECT kind, key, name FROM labels`)
	if err != nil {
		return labels, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, key, name string
		if err := rows.Scan(&kind, &key, &name); err != nil {
			return labels, err
		}
		switch kind {
		case "vlan":
			if id, err := strconv.ParseUint(key, 10, 16); err == nil {
				labels.VLANs[uint16(id)] = name
			}
		case "ip":
			if ip, err := netip.ParseAddr(key); err == nil {
				labels.IPs[ip] = name
			}
		}
	}
	return labels, rows.Err()
}

// SetVLANLabel names a VLAN; an empty name removes the label.
func (s *Store) SetVLANLabel(ctx context.Context, vlan uint16, name string) error {
	return s.setLabel(ctx, "vlan", strconv.Itoa(int(vlan)), name)
}

// SetIPLabel names an IP address; an empty name removes the label.
func (s *Store) SetIPLabel(ctx context.Context, ip netip.Addr, name string) error {
	return s.setLabel(ctx, "ip", ip.Unmap().String(), name)
}

func (s *Store) setLabel(ctx context.Context, kind, key, name string) error {
	if name == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM labels WHERE kind=? AND key=?`, kind, key)
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO labels (kind, key, name) VALUES (?, ?, ?)
		ON CONFLICT (kind, key) DO UPDATE SET name=excluded.name`, kind, key, name)
	return err
}

func (s *Store) Prune(ctx context.Context, cutoff time.Time, maxRows int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM connections WHERE started_at < ? OR id NOT IN
        (SELECT id FROM connections ORDER BY started_at DESC, id DESC LIMIT ?)`,
		cutoff.UnixNano(), maxRows)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM dns_queries WHERE queried_at < ? OR id NOT IN
		(SELECT id FROM dns_queries ORDER BY queried_at DESC, id DESC LIMIT ?)`, cutoff.UnixNano(), maxRows)
	return err
}

func (s *Store) AddDNS(ctx context.Context, q DNSQuery) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO dns_queries (queried_at, name, type, server_ip) VALUES (?, ?, ?, ?)`,
		q.QueriedAt.UnixNano(), q.Name, q.Type, q.ServerIP.String())
	return err
}

func (s *Store) ListDNS(ctx context.Context, since time.Time, limit int) ([]DNSQuery, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, queried_at, name, type, server_ip FROM dns_queries
		WHERE queried_at >= ? ORDER BY queried_at DESC, id DESC LIMIT ?`, since.UnixNano(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	queries := make([]DNSQuery, 0)
	for rows.Next() {
		var q DNSQuery
		var stamp int64
		var ip string
		if err := rows.Scan(&q.ID, &stamp, &q.Name, &q.Type, &ip); err != nil {
			return nil, err
		}
		q.QueriedAt = time.Unix(0, stamp).UTC()
		if q.ServerIP, err = netip.ParseAddr(ip); err != nil {
			return nil, err
		}
		queries = append(queries, q)
	}
	return queries, rows.Err()
}
