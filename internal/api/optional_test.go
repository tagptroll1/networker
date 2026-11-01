package api

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagptroll1/networker/internal/history"
	"github.com/tagptroll1/networker/internal/snitch"
	"github.com/tagptroll1/networker/internal/tracker"
)

func status(t *testing.T, s *Server, path string, out any) int {
	t.Helper()
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest("GET", path, nil))
	if out != nil && response.Code == 200 {
		if err := json.Unmarshal(response.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: %v in %s", path, err, response.Body)
		}
	}
	return response.Code
}

// The desktop panel's feed: no database, no locations, no snitch.
func TestLiveOnly(t *testing.T) {
	s := &Server{Live: tracker.New(nil, &history.Discard{}), Health: &Health{}}
	var config struct {
		Origin          *Origin
		Router, History bool
		Snitch          bool
	}
	if code := status(t, s, "/api/config", &config); code != 200 || config.History || config.Snitch {
		t.Fatalf("config: %d %+v", code, config)
	}
	var flows []any
	if code := status(t, s, "/api/flows", &flows); code != 200 || len(flows) != 0 {
		t.Fatalf("flows: %d %v", code, flows)
	}
	for _, path := range []string{"/api/connections", "/api/dns", "/api/labels", "/api/snitch/apps", "/api/snitch/alerts", "/api/snitch/rules"} {
		if code := status(t, s, path, nil); code != 404 {
			t.Errorf("%s: %d, want 404", path, code)
		}
	}
}

func TestHealth(t *testing.T) {
	health := &Health{}
	s := &Server{Live: tracker.New(nil, &history.Discard{}), Health: health}
	var got struct {
		Now        int64   `json:"now"`
		LastPollOK int64   `json:"last_poll_ok"`
		LastError  *string `json:"last_error"`
		DNSError   *string `json:"dns_error"`
	}
	if code := status(t, s, "/api/health", &got); code != 200 || got.Now == 0 || got.LastPollOK != 0 {
		t.Fatalf("before polling: %d %+v", code, got)
	}
	health.PollFailed(errors.New("boom"))
	health.DNSFailed(errors.New("dns"))
	status(t, s, "/api/health", &got)
	if got.LastError == nil || *got.LastError != "boom" || got.DNSError == nil || *got.DNSError != "dns" {
		t.Fatalf("after failure: %+v", got)
	}
	at := time.Now()
	health.PollOK(at)
	got.LastError = nil
	status(t, s, "/api/health", &got)
	if got.LastPollOK != at.UnixMilli() || got.LastError != nil {
		t.Fatalf("after recovery: %+v", got)
	}
}

func TestSnitchRoutes(t *testing.T) {
	rules := []snitch.Rule{{App: "a", Host: "bad.com"}}
	monitor, err := snitch.Open(snitch.Options{Path: filepath.Join(t.TempDir(), "snitch.db"), Watch: []string{"a b"},
		Retention: time.Hour, MaxDestinations: 10}, snitch.NewPolicy(rules, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	now := time.Now()
	monitor.Blocked(now, "a b", "bad.com", netip.MustParseAddr("1.2.3.4"))
	monitor.Blocked(now, "a", "bad.com", netip.MustParseAddr("1.2.3.4"))
	s := &Server{Live: tracker.New(nil, &history.Discard{}), Snitch: monitor}

	var config struct{ Snitch bool }
	if status(t, s, "/api/config", &config); !config.Snitch {
		t.Error("config does not announce the snitch")
	}
	var apps []snitch.App
	if code := status(t, s, "/api/snitch/apps", &apps); code != 200 || len(apps) != 2 {
		t.Fatalf("apps: %d %+v", code, apps)
	}
	// App names can hold spaces, since they derive from process arguments.
	var destinations []snitch.Destination
	if code := status(t, s, "/api/snitch/apps/a%20b", &destinations); code != 200 || len(destinations) != 1 || destinations[0].Blocked != 1 {
		t.Fatalf("destinations: %d %+v", code, destinations)
	}
	if status(t, s, "/api/snitch/apps/a", &destinations); destinations[0].Rule == "" {
		t.Errorf("rule not reported: %+v", destinations[0])
	}
	var result struct {
		Seq    uint64         `json:"seq"`
		Alerts []snitch.Alert `json:"alerts"`
	}
	if code := status(t, s, "/api/snitch/alerts", &result); code != 200 || result.Seq != 1 || len(result.Alerts) != 1 {
		t.Fatalf("alerts: %d %+v", code, result)
	}
	if status(t, s, "/api/snitch/alerts?after=1", &result); len(result.Alerts) != 0 {
		t.Fatalf("alerts after: %+v", result)
	}
	if code := status(t, s, "/api/snitch/alerts?after=x", nil); code != 400 {
		t.Errorf("bad after: %d", code)
	}
	var policy struct {
		Enforcing bool
		Rules     []snitch.Rule
	}
	if code := status(t, s, "/api/snitch/rules", &policy); code != 200 || policy.Enforcing || len(policy.Rules) != 1 {
		t.Fatalf("rules: %d %+v", code, policy)
	}
}
