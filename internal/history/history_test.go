package history

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "history.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	base := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	original := Connection{StartedAt: base, App: "spotify", RemoteIP: netip.MustParseAddr("1.1.1.1"),
		RemotePort: 443, Protocol: "tcp", Direction: "outbound", Status: "observed", Sent: 120}
	id, err := store.Add(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	original.ID, original.Status, original.Received = id, "established", 200
	if err := store.Update(ctx, original); err != nil {
		t.Fatal(err)
	}
	later := original
	later.StartedAt = base.Add(time.Nanosecond)
	if _, err := store.Add(ctx, later); err != nil {
		t.Fatal(err)
	}
	records, err := store.List(ctx, base.Add(time.Nanosecond), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !records[0].StartedAt.Equal(later.StartedAt) {
		t.Fatalf("since filter: %+v", records)
	}
	if err := store.Prune(ctx, base.Add(-time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	records, err = store.List(ctx, time.Unix(0, 0), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Status != "established" {
		t.Fatalf("retention/update: %+v", records)
	}
}

func TestMigratesExistingHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE connections (id INTEGER PRIMARY KEY, started_at INTEGER NOT NULL,
		app TEXT NOT NULL, remote_ip TEXT NOT NULL, remote_port INTEGER NOT NULL, protocol TEXT NOT NULL,
		direction TEXT NOT NULL, status TEXT NOT NULL, sent_bytes INTEGER NOT NULL, received_bytes INTEGER NOT NULL);
		INSERT INTO connections (started_at, app, remote_ip, remote_port, protocol, direction, status, sent_bytes, received_bytes)
		VALUES (1, 'old', '127.0.0.1', 80, 'tcp', 'inbound', 'observed', 10, 20)`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rows, err := store.List(context.Background(), time.Unix(0, 0), 10)
	if err != nil || len(rows) != 1 || rows[0].App != "old" || rows[0].PID != 0 {
		t.Fatalf("migration: %+v, %v", rows, err)
	}
	rows[0].PID, rows[0].Local, rows[0].Executable, rows[0].Unit = 123, "127.0.0.1:80", "/usr/bin/old", "old.service"
	if err := store.Update(context.Background(), rows[0]); err != nil {
		t.Fatal(err)
	}
	rows, err = store.List(context.Background(), time.Unix(0, 0), 10)
	if err != nil || rows[0].PID != 123 || rows[0].Local != "127.0.0.1:80" || rows[0].Executable != "/usr/bin/old" || rows[0].Unit != "old.service" {
		t.Fatalf("attribution: %+v, %v", rows, err)
	}
}

func TestDNSHistoryAndRetention(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	base := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"old.example", "new.example"} {
		if err := store.AddDNS(ctx, DNSQuery{QueriedAt: base, Name: name, Type: "AAAA", ServerIP: netip.MustParseAddr("127.0.0.53")}); err != nil {
			t.Fatal(err)
		}
	}
	queries, err := store.ListDNS(ctx, base, 1)
	if err != nil || len(queries) != 1 || queries[0].Name != "new.example" {
		t.Fatalf("list: %+v %v", queries, err)
	}
	if err := store.Prune(ctx, base.Add(-time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	queries, err = store.ListDNS(ctx, time.Unix(0, 0), 10)
	if err != nil || len(queries) != 1 || queries[0].Name != "new.example" {
		t.Fatalf("prune: %+v %v", queries, err)
	}
}
