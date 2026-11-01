package main

import (
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tagptroll1/networker/internal/api"
)

// config holds what the NETWORKER_* environment asks for. Every part beyond
// the HTTP API is optional, so one binary serves a full dashboard, a router
// monitor, a desktop widget's live feed, and per-app egress watching.
type config struct {
	listen      string
	cityDB      string
	asnDB       string
	origin      *api.Origin
	capture     bool
	history     bool
	historyDB   string
	retention   time.Duration
	maxRecords  int
	dashboard   bool
	router      routerConfig
	snitch      bool
	snitchDB    string
	rulesFile   string
	enforce     bool
	watch       []string
	quiet       []string
	learn       time.Duration
	snitchKeep  time.Duration
	snitchLimit int
}

type routerConfig struct{ url, user, passwordFile, caFile string }

// known lists every variable, so a misspelled one fails instead of silently
// leaving, say, blocking off.
var known = map[string]bool{
	"NETWORKER_LISTEN": true, "NETWORKER_CITY_DB": true, "NETWORKER_ASN_DB": true,
	"NETWORKER_ORIGIN_LAT": true, "NETWORKER_ORIGIN_LON": true, "NETWORKER_CAPTURE": true,
	"NETWORKER_HISTORY": true, "NETWORKER_HISTORY_DB": true, "NETWORKER_HISTORY_RETENTION": true,
	"NETWORKER_HISTORY_MAX_RECORDS": true, "NETWORKER_DASHBOARD": true, "NETWORKER_ROUTER_URL": true,
	"NETWORKER_ROUTER_USER": true, "NETWORKER_ROUTER_PASSWORD_FILE": true, "NETWORKER_ROUTER_CA": true,
	"NETWORKER_SNITCH": true, "NETWORKER_SNITCH_DB": true, "NETWORKER_SNITCH_RULES": true,
	"NETWORKER_SNITCH_ENFORCE": true, "NETWORKER_SNITCH_WATCH": true, "NETWORKER_SNITCH_QUIET": true,
	"NETWORKER_SNITCH_LEARN": true, "NETWORKER_SNITCH_RETENTION": true, "NETWORKER_SNITCH_MAX_DESTINATIONS": true,
}

type envReader struct {
	values map[string]string
	errs   []string
}

func (e *envReader) text(name, fallback string) string {
	if value := e.values[name]; value != "" {
		return value
	}
	return fallback
}

func (e *envReader) boolean(name string, fallback bool) bool {
	raw := e.values[name]
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		e.errs = append(e.errs, name+" must be true or false")
		return fallback
	}
	return value
}

func (e *envReader) duration(name string, fallback time.Duration) time.Duration {
	raw := e.values[name]
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < 0 {
		e.errs = append(e.errs, name+" must be a duration such as 720h")
		return fallback
	}
	return value
}

func (e *envReader) positive(name string, fallback int) int {
	raw := e.values[name]
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		e.errs = append(e.errs, name+" must be a positive number")
		return fallback
	}
	return value
}

func (e *envReader) coordinate(name string) float64 {
	raw := e.values[name]
	if raw == "" {
		return math.NaN()
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		e.errs = append(e.errs, name+" must be a number")
		return math.NaN()
	}
	return value
}

func (e *envReader) list(name string) []string {
	var items []string
	for _, item := range strings.Split(e.values[name], ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// loadConfig reads os.Environ-style entries.
func loadConfig(environ []string, dashboardBuilt bool) (config, error) {
	reader := &envReader{values: make(map[string]string)}
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		reader.values[name] = value
		if strings.HasPrefix(name, "NETWORKER_") && !known[name] {
			reader.errs = append(reader.errs, "unknown variable "+name)
		}
	}
	state := reader.text("XDG_STATE_HOME", filepath.Join(reader.values["HOME"], ".local/state"))
	c := config{
		listen:      reader.text("NETWORKER_LISTEN", "127.0.0.1:8765"),
		cityDB:      reader.values["NETWORKER_CITY_DB"],
		asnDB:       reader.values["NETWORKER_ASN_DB"],
		capture:     reader.boolean("NETWORKER_CAPTURE", true),
		history:     reader.boolean("NETWORKER_HISTORY", true),
		historyDB:   reader.text("NETWORKER_HISTORY_DB", filepath.Join(state, "networker", "history.db")),
		retention:   reader.duration("NETWORKER_HISTORY_RETENTION", 30*24*time.Hour),
		maxRecords:  reader.positive("NETWORKER_HISTORY_MAX_RECORDS", 50000),
		dashboard:   reader.boolean("NETWORKER_DASHBOARD", dashboardBuilt),
		snitch:      reader.boolean("NETWORKER_SNITCH", false),
		snitchDB:    reader.text("NETWORKER_SNITCH_DB", filepath.Join(state, "networker", "snitch.db")),
		rulesFile:   reader.values["NETWORKER_SNITCH_RULES"],
		enforce:     reader.boolean("NETWORKER_SNITCH_ENFORCE", false),
		watch:       reader.list("NETWORKER_SNITCH_WATCH"),
		quiet:       reader.list("NETWORKER_SNITCH_QUIET"),
		learn:       reader.duration("NETWORKER_SNITCH_LEARN", 24*time.Hour),
		snitchKeep:  reader.duration("NETWORKER_SNITCH_RETENTION", 90*24*time.Hour),
		snitchLimit: reader.positive("NETWORKER_SNITCH_MAX_DESTINATIONS", 20000),
		router: routerConfig{
			url:          reader.values["NETWORKER_ROUTER_URL"],
			user:         reader.text("NETWORKER_ROUTER_USER", "networker"),
			passwordFile: reader.values["NETWORKER_ROUTER_PASSWORD_FILE"],
			caFile:       reader.values["NETWORKER_ROUTER_CA"],
		},
	}
	lat, lon := reader.coordinate("NETWORKER_ORIGIN_LAT"), reader.coordinate("NETWORKER_ORIGIN_LON")
	require := func(ok bool, message string) {
		if !ok {
			reader.errs = append(reader.errs, message)
		}
	}
	require(math.IsNaN(lat) == math.IsNaN(lon), "set both NETWORKER_ORIGIN_LAT and NETWORKER_ORIGIN_LON, or neither")
	if !math.IsNaN(lat) && !math.IsNaN(lon) {
		require(lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180, "origin coordinates out of range")
		c.origin = &api.Origin{Latitude: lat, Longitude: lon}
	}
	require(api.Loopback(c.listen), "NETWORKER_LISTEN must be a numeric loopback address and port")
	require(c.retention > 0, "NETWORKER_HISTORY_RETENTION must be positive")
	require(c.asnDB == "" || c.cityDB != "", "NETWORKER_ASN_DB needs NETWORKER_CITY_DB")
	require(c.capture || c.router.url != "", "nothing to collect: NETWORKER_CAPTURE is off and NETWORKER_ROUTER_URL is unset")
	require(!c.dashboard || dashboardBuilt, "NETWORKER_DASHBOARD is on but this binary was built without it")
	require(!c.dashboard || c.history, "NETWORKER_DASHBOARD needs NETWORKER_HISTORY")
	require(!c.snitch || c.capture, "NETWORKER_SNITCH needs NETWORKER_CAPTURE: routers report no process details")
	require(!c.enforce || c.snitch, "NETWORKER_SNITCH_ENFORCE needs NETWORKER_SNITCH")
	require(!c.enforce || c.rulesFile != "", "NETWORKER_SNITCH_ENFORCE needs NETWORKER_SNITCH_RULES")
	require(c.router.url == "" || (c.router.passwordFile != "" && c.router.caFile != ""),
		"NETWORKER_ROUTER_URL needs NETWORKER_ROUTER_PASSWORD_FILE and NETWORKER_ROUTER_CA")
	if len(reader.errs) != 0 {
		return c, fmt.Errorf("%s", strings.Join(reader.errs, "; "))
	}
	return c, nil
}
