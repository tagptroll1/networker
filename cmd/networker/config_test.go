package main

import (
	"strings"
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	c, err := loadConfig([]string{"HOME=/home/x"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.listen != "127.0.0.1:8765" || !c.capture || !c.history || !c.dashboard || c.snitch || c.enforce {
		t.Errorf("%+v", c)
	}
	if c.historyDB != "/home/x/.local/state/networker/history.db" || c.origin != nil || c.retention != 30*24*time.Hour {
		t.Errorf("%+v", c)
	}
}

func TestConfigLiveOnly(t *testing.T) {
	c, err := loadConfig([]string{"NETWORKER_HISTORY=false", "NETWORKER_DASHBOARD=false", "NETWORKER_LISTEN=127.0.0.1:8766"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.history || c.dashboard || c.listen != "127.0.0.1:8766" {
		t.Errorf("%+v", c)
	}
}

func TestConfigHeadlessDefaultsDashboardOff(t *testing.T) {
	if c, err := loadConfig(nil, false); err != nil || c.dashboard {
		t.Errorf("%+v, %v", c, err)
	}
}

func TestConfigSnitch(t *testing.T) {
	c, err := loadConfig([]string{"NETWORKER_SNITCH=1", "NETWORKER_SNITCH_ENFORCE=true", "NETWORKER_SNITCH_RULES=/r.json",
		"NETWORKER_SNITCH_WATCH=a, b,,", "NETWORKER_SNITCH_LEARN=1h", "NETWORKER_ORIGIN_LAT=59.9", "NETWORKER_ORIGIN_LON=10.7"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !c.enforce || len(c.watch) != 2 || c.watch[1] != "b" || c.learn != time.Hour || c.origin.Latitude != 59.9 {
		t.Errorf("%+v", c)
	}
}

func TestConfigRouterOnly(t *testing.T) {
	c, err := loadConfig([]string{"NETWORKER_CAPTURE=false", "NETWORKER_ROUTER_URL=https://r", "NETWORKER_ROUTER_PASSWORD_FILE=/p", "NETWORKER_ROUTER_CA=/c"}, true)
	if err != nil || c.capture || c.router.user != "networker" {
		t.Errorf("%+v, %v", c, err)
	}
}

func TestConfigRejects(t *testing.T) {
	for want, environ := range map[string][]string{
		"unknown variable NETWORKER_SNITCH_ENFROCE": {"NETWORKER_SNITCH_ENFROCE=true"},
		"NETWORKER_LISTEN":                          {"NETWORKER_LISTEN=0.0.0.0:80"},
		"must be true or false":                     {"NETWORKER_HISTORY=maybe"},
		"must be a duration":                        {"NETWORKER_SNITCH_LEARN=soon"},
		"must be a positive number":                 {"NETWORKER_HISTORY_MAX_RECORDS=0"},
		"set both":                                  {"NETWORKER_ORIGIN_LAT=1"},
		"out of range":                              {"NETWORKER_ORIGIN_LAT=91", "NETWORKER_ORIGIN_LON=0"},
		"needs NETWORKER_CITY_DB":                   {"NETWORKER_ASN_DB=/a"},
		"nothing to collect":                        {"NETWORKER_CAPTURE=false"},
		"needs NETWORKER_HISTORY":                   {"NETWORKER_HISTORY=false"},
		"needs NETWORKER_CAPTURE":                   {"NETWORKER_CAPTURE=false", "NETWORKER_ROUTER_URL=u", "NETWORKER_ROUTER_PASSWORD_FILE=p", "NETWORKER_ROUTER_CA=c", "NETWORKER_SNITCH=true"},
		"needs NETWORKER_SNITCH_RULES":              {"NETWORKER_SNITCH=true", "NETWORKER_SNITCH_ENFORCE=true"},
		"needs NETWORKER_ROUTER_PASSWORD_FILE":      {"NETWORKER_ROUTER_URL=u"},
	} {
		if _, err := loadConfig(environ, true); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: got %v, want %q", environ, err, want)
		}
	}
	if _, err := loadConfig([]string{"NETWORKER_SNITCH_ENFORCE=true", "NETWORKER_SNITCH_RULES=/r"}, true); err == nil {
		t.Error("enforcing without snitch accepted")
	}
	if _, err := loadConfig([]string{"NETWORKER_DASHBOARD=true"}, false); err == nil {
		t.Error("dashboard without one built accepted")
	}
}
