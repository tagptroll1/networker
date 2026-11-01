// Package snitch tracks which destinations each app talks to, and can refuse
// connections the configured rules name.
package snitch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tagptroll1/networker/internal/capture"
)

// Everyone is the rule app matching all processes.
const Everyone = "*"

// A DNS answer's TTL can be shorter than a client's own cache, so learned
// addresses stay blocked at least this long.
const minHold = time.Hour

// Rule names what to refuse: one app or Everyone, and a domain with its
// subdomains or an address range.
type Rule struct {
	App  string `json:"app"`
	Host string `json:"host,omitempty"`
	CIDR string `json:"cidr,omitempty"`
}

func (r Rule) String() string {
	if r.Host != "" {
		return r.App + " -> " + r.Host
	}
	return r.App + " -> " + r.CIDR
}

// ParseRules reads a JSON array of rules.
func ParseRules(data []byte) ([]Rule, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var rules []Rule
	if err := decoder.Decode(&rules); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	for i, rule := range rules {
		if rule.App == "" {
			return nil, fmt.Errorf("rule %d: app is required, use %q for everyone", i, Everyone)
		}
		if (rule.Host == "") == (rule.CIDR == "") {
			return nil, fmt.Errorf("rule %d: set exactly one of host and cidr", i)
		}
		if rule.Host != "" {
			rules[i].Host = strings.ToLower(strings.TrimSuffix(rule.Host, "."))
			if strings.ContainsAny(rules[i].Host, "* /") || rules[i].Host == "" {
				return nil, fmt.Errorf("rule %d: host %q must be a plain domain; subdomains are included", i, rule.Host)
			}
		} else if _, err := parsePrefix(rule.CIDR); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return rules, nil
}

// LoadRules reads a rules file.
func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRules(data)
}

func parsePrefix(text string) (netip.Prefix, error) {
	if addr, err := netip.ParseAddr(text); err == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		return prefix, fmt.Errorf("invalid cidr %q", text)
	}
	return prefix.Masked(), nil
}

// Enforcer is the kernel side of blocking.
type Enforcer interface {
	SetEnforcing(bool) error
	AssignApp(pid, app uint32) error
	Block(app uint32, prefix netip.Prefix) error
	Unblock(app uint32, prefix netip.Prefix) error
}

type learned struct {
	app    uint32
	prefix netip.Prefix
}

// Policy turns rules into kernel state. Without an enforcer it is a dry run:
// connections are still matched, so the rules can be judged before they bite.
type Policy struct {
	rules    []Rule
	prefixes map[int]netip.Prefix
	ids      map[string]uint32
	enforcer Enforcer
	identify func(uint32) string

	mu      sync.Mutex
	expires map[learned]time.Time
}

// NewPolicy assumes validated rules. enforcer may be nil.
func NewPolicy(rules []Rule, enforcer Enforcer, identify func(uint32) string) *Policy {
	p := &Policy{rules: rules, prefixes: make(map[int]netip.Prefix), ids: make(map[string]uint32),
		enforcer: enforcer, identify: identify, expires: make(map[learned]time.Time)}
	for i, rule := range rules {
		if rule.App != Everyone && p.ids[rule.App] == 0 {
			p.ids[rule.App] = uint32(len(p.ids) + 1)
		}
		if rule.CIDR != "" {
			p.prefixes[i], _ = parsePrefix(rule.CIDR)
		}
	}
	return p
}

// Enforcing reports whether matches are refused rather than only flagged.
func (p *Policy) Enforcing() bool { return p.enforcer != nil }

// Rules lists the configured rules.
func (p *Policy) Rules() []Rule { return p.rules }

// Start loads address rules, identifies running processes, then arms the
// kernel checks so nothing is judged against a half-loaded policy.
func (p *Policy) Start(pids []uint32) error {
	if p.enforcer == nil {
		return nil
	}
	for i, prefix := range p.prefixes {
		if err := p.enforcer.Block(p.ids[p.rules[i].App], prefix); err != nil {
			return fmt.Errorf("load rule %s: %w", p.rules[i], err)
		}
	}
	for _, pid := range pids {
		p.Exec(pid)
	}
	return p.enforcer.SetEnforcing(true)
}

// Exec identifies a process that just started a new program. Other apps have no
// rules of their own, so they need no kernel entry.
func (p *Policy) Exec(pid uint32) {
	if p.enforcer == nil || len(p.ids) == 0 {
		return
	}
	if id := p.ids[p.identify(pid)]; id != 0 {
		// The process can exit first; then there is nothing left to govern.
		_ = p.enforcer.AssignApp(pid, id)
	}
}

// Answers blocks addresses DNS just tied to a blocked domain.
func (p *Policy) Answers(answers []capture.DNSAnswer, now time.Time) {
	if p.enforcer == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, answer := range answers {
		if !answer.Address.IsValid() {
			continue
		}
		addr := answer.Address.Unmap()
		for _, rule := range p.rules {
			if rule.Host == "" || !hostMatches(answer.Name, rule.Host) {
				continue
			}
			item := learned{p.ids[rule.App], netip.PrefixFrom(addr, addr.BitLen())}
			if err := p.enforcer.Block(item.app, item.prefix); err != nil {
				log.Printf("snitch: block %s for %s: %v", addr, rule, err)
				continue
			}
			p.expires[item] = now.Add(max(answer.TTL, minHold))
		}
	}
}

// Sweep lets go of learned addresses whose hold ran out.
func (p *Policy) Sweep(now time.Time) {
	if p.enforcer == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for item, expires := range p.expires {
		if expires.After(now) {
			continue
		}
		if err := p.enforcer.Unblock(item.app, item.prefix); err != nil {
			log.Printf("snitch: unblock %s: %v", item.prefix, err)
		}
		delete(p.expires, item)
	}
}

// Match returns the first rule covering a connection, or "".
func (p *Policy) Match(app, host string, ip netip.Addr) string {
	ip = ip.Unmap()
	for i, rule := range p.rules {
		if rule.App != Everyone && rule.App != app {
			continue
		}
		if rule.Host != "" && hostMatches(host, rule.Host) {
			return rule.String()
		}
		if prefix, ok := p.prefixes[i]; ok && ip.IsValid() && prefix.Contains(ip) {
			return rule.String()
		}
	}
	return ""
}

func hostMatches(name, host string) bool {
	return name == host || strings.HasSuffix(name, "."+host)
}
