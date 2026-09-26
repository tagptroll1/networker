// Package router reads other LAN devices' traffic from a MikroTik RouterOS
// REST API: connection tracking, DHCP leases, subnets/VLANs and the DNS cache.
// Only GET requests are made.
package router

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tagptroll1/networker/internal/capture"
	"github.com/tagptroll1/networker/internal/history"
)

// Connection is one routed connection seen from the LAN device's side.
type Connection struct {
	ID          string
	Protocol    string
	Device      history.Device
	Local       netip.AddrPort
	Remote      netip.AddrPort
	Inbound     bool
	Established bool
	Sent        uint64
	Received    uint64
}

type Router struct {
	base     *url.URL
	user     string
	password string
	client   *http.Client

	mu      sync.RWMutex
	network *network
}

// New trusts only the given PEM CA, so a router certificate signed by its
// own local CA works without trusting it system-wide.
func New(base, user, password string, caPEM []byte) (*Router, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("router URL must be https://host")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("router CA file has no PEM certificate")
	}
	return &Router{base: u, user: user, password: password, client: &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}}, nil
}

func (r *Router) get(ctx context.Context, path string, fields string, out any) error {
	u := r.base.JoinPath("rest", path)
	u.RawQuery = url.Values{".proplist": {fields}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	request.SetBasicAuth(r.user, r.password)
	response, err := r.client.Do(request)
	if err != nil {
		return fmt.Errorf("router %s: %w", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("router %s: %w", path, err)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("router %s: %s: %s", path, response.Status, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("router %s: %w", path, err)
	}
	return nil
}

// Refresh reloads subnets, VLANs and DHCP leases.
func (r *Router) Refresh(ctx context.Context) error {
	var addresses []address
	var vlans []vlan
	var bridges []bridge
	var members []member
	var leases []lease
	for _, request := range []struct {
		path, fields string
		out          any
	}{
		{"ip/address", "address,interface,disabled,invalid", &addresses},
		{"interface/vlan", "name,vlan-id", &vlans},
		{"interface/bridge", "name,pvid,vlan-filtering", &bridges},
		{"interface/list/member", "list,interface,disabled", &members},
		{"ip/dhcp-server/lease", "address,mac-address,host-name,comment", &leases},
	} {
		if err := r.get(ctx, request.path, request.fields, request.out); err != nil {
			return err
		}
	}
	n := newNetwork(addresses, vlans, bridges, members, leases)
	r.mu.Lock()
	r.network = n
	r.mu.Unlock()
	return nil
}

func (r *Router) current() *network {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.network
}

// Lookup describes a LAN address, or returns nil when it is not on a router subnet.
func (r *Router) Lookup(ip netip.Addr) *history.Device {
	n := r.current()
	if n == nil {
		return nil
	}
	d, ok := n.device(ip)
	if !ok {
		return nil
	}
	return &d
}

// Connections returns routed TCP/UDP connections of LAN devices. Connections
// involving an address for which skip returns true are left out; this host's
// own traffic is already observed with process details by eBPF.
func (r *Router) Connections(ctx context.Context, skip func(netip.Addr) bool) ([]Connection, error) {
	n := r.current()
	if n == nil {
		return nil, errors.New("router network not loaded")
	}
	var entries []entry
	if err := r.get(ctx, "ip/firewall/connection", ".id,protocol,src-address,src-port,dst-address,dst-port,"+
		"reply-src-address,reply-src-port,reply-dst-address,reply-dst-port,orig-bytes,repl-bytes,tcp-state", &entries); err != nil {
		return nil, err
	}
	result := make([]Connection, 0, len(entries))
	for _, e := range entries {
		if c, ok := n.connection(e, skip); ok {
			result = append(result, c)
		}
	}
	return result, nil
}

// DNS returns address answers from the router's DNS cache, named by the
// queried name at the start of any CNAME chain.
func (r *Router) DNS(ctx context.Context) ([]capture.DNSAnswer, error) {
	var records []dnsRecord
	if err := r.get(ctx, "ip/dns/cache", "name,type,data,ttl", &records); err != nil {
		return nil, err
	}
	return dnsAnswers(records), nil
}

type address struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Disabled  string `json:"disabled"`
	Invalid   string `json:"invalid"`
}

type vlan struct {
	Name string `json:"name"`
	ID   string `json:"vlan-id"`
}

type bridge struct {
	Name          string `json:"name"`
	PVID          string `json:"pvid"`
	VLANFiltering string `json:"vlan-filtering"`
}

type member struct {
	List      string `json:"list"`
	Interface string `json:"interface"`
	Disabled  string `json:"disabled"`
}

type lease struct {
	Address  string `json:"address"`
	MAC      string `json:"mac-address"`
	HostName string `json:"host-name"`
	Comment  string `json:"comment"`
}

type entry struct {
	ID              string `json:".id"`
	Protocol        string `json:"protocol"`
	SrcAddress      string `json:"src-address"`
	SrcPort         string `json:"src-port"`
	DstAddress      string `json:"dst-address"`
	ReplySrcAddress string `json:"reply-src-address"`
	ReplySrcPort    string `json:"reply-src-port"`
	ReplyDstAddress string `json:"reply-dst-address"`
	OrigBytes       string `json:"orig-bytes"`
	ReplBytes       string `json:"repl-bytes"`
	TCPState        string `json:"tcp-state"`
}

type dnsRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  string `json:"ttl"`
}

type subnet struct {
	prefix netip.Prefix
	iface  string
	vlan   uint16
}

type network struct {
	subnets []subnet
	own     map[netip.Addr]bool
	leases  map[netip.Addr]lease
}

func newNetwork(addresses []address, vlans []vlan, bridges []bridge, members []member, leases []lease) *network {
	ids := make(map[string]uint16)
	for _, v := range vlans {
		if id, err := strconv.ParseUint(v.ID, 10, 12); err == nil {
			ids[v.Name] = uint16(id)
		}
	}
	// A VLAN-filtering bridge carries its own untagged traffic in its PVID.
	for _, b := range bridges {
		if id, err := strconv.ParseUint(b.PVID, 10, 12); err == nil && b.VLANFiltering == "true" {
			ids[b.Name] = uint16(id)
		}
	}
	wan := make(map[string]bool)
	for _, m := range members {
		if m.List == "WAN" && m.Disabled != "true" {
			wan[m.Interface] = true
		}
	}
	n := &network{own: make(map[netip.Addr]bool), leases: make(map[netip.Addr]lease)}
	for _, a := range addresses {
		prefix, err := netip.ParsePrefix(a.Address)
		if err != nil || a.Disabled == "true" {
			continue
		}
		n.own[prefix.Addr()] = true
		if !wan[a.Interface] && a.Invalid != "true" {
			n.subnets = append(n.subnets, subnet{prefix.Masked(), a.Interface, ids[a.Interface]})
		}
	}
	for _, l := range leases {
		if ip, err := netip.ParseAddr(l.Address); err == nil {
			n.leases[ip] = l
		}
	}
	return n
}

// device describes a LAN client address, excluding the router's own.
func (n *network) device(ip netip.Addr) (history.Device, bool) {
	ip = ip.Unmap()
	if n.own[ip] {
		return history.Device{}, false
	}
	for _, s := range n.subnets {
		if s.prefix.Contains(ip) {
			d := history.Device{IP: ip, VLAN: s.vlan, Interface: s.iface}
			if l, ok := n.leases[ip]; ok {
				d.MAC, d.Name = l.MAC, l.HostName
				// A lease comment is the admin's own name for the device.
				if l.Comment != "" {
					d.Name = l.Comment
				}
			}
			return d, true
		}
	}
	return history.Device{}, false
}

func endpoint(ip, port string) netip.AddrPort {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(p))
}

// connection orients a conntrack entry from the LAN device's side. The
// original source opened it; the reply source is who actually answered
// (after destination NAT).
func (n *network) connection(e entry, skip func(netip.Addr) bool) (Connection, bool) {
	if e.Protocol != "tcp" && e.Protocol != "udp" {
		return Connection{}, false
	}
	opener, answerer := endpoint(e.SrcAddress, e.SrcPort), endpoint(e.ReplySrcAddress, e.ReplySrcPort)
	if !opener.IsValid() || !answerer.IsValid() {
		return Connection{}, false
	}
	for _, raw := range []string{e.SrcAddress, e.DstAddress, e.ReplySrcAddress, e.ReplyDstAddress} {
		if ip, err := netip.ParseAddr(raw); err == nil && skip != nil && skip(ip.Unmap()) {
			return Connection{}, false
		}
	}
	orig, err1 := strconv.ParseUint(e.OrigBytes, 10, 64)
	repl, err2 := strconv.ParseUint(e.ReplBytes, 10, 64)
	if err1 != nil || err2 != nil {
		return Connection{}, false
	}
	c := Connection{ID: e.ID, Protocol: e.Protocol, Established: e.TCPState == "established"}
	if d, ok := n.device(opener.Addr()); ok {
		c.Device, c.Local, c.Remote, c.Sent, c.Received = d, opener, answerer, orig, repl
	} else if d, ok := n.device(answerer.Addr()); ok {
		c.Device, c.Local, c.Remote, c.Sent, c.Received, c.Inbound = d, answerer, opener, repl, orig, true
	} else {
		return Connection{}, false
	}
	// Traffic to or from the router itself (DNS, WinBox) does not leave it.
	if n.own[c.Remote.Addr()] {
		return Connection{}, false
	}
	return c, true
}

func dnsAnswers(records []dnsRecord) []capture.DNSAnswer {
	alias := make(map[string]string)
	for _, r := range records {
		if r.Type == "CNAME" {
			alias[strings.TrimSuffix(r.Data, ".")] = r.Name
		}
	}
	answers := make([]capture.DNSAnswer, 0)
	for _, r := range records {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		ip, err := netip.ParseAddr(r.Data)
		ttl, ok := duration(r.TTL)
		if err != nil || !ok || ttl <= 0 {
			continue
		}
		name := r.Name
		for range 8 {
			previous, found := alias[name]
			if !found {
				break
			}
			name = previous
		}
		answers = append(answers, capture.DNSAnswer{Name: name, Address: ip, TTL: min(ttl, time.Hour)})
	}
	return answers
}

// duration parses RouterOS durations such as "1w2d3h4m5s" or "250ms".
func duration(text string) (time.Duration, bool) {
	units := []struct {
		suffix string
		size   time.Duration
	}{{"ms", time.Millisecond}, {"w", 7 * 24 * time.Hour}, {"d", 24 * time.Hour}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}}
	var total time.Duration
	for text != "" {
		i := 0
		for i < len(text) && text[i] >= '0' && text[i] <= '9' {
			i++
		}
		if i == 0 {
			return 0, false
		}
		value, err := strconv.Atoi(text[:i])
		if err != nil {
			return 0, false
		}
		text = text[i:]
		matched := false
		for _, unit := range units {
			if strings.HasPrefix(text, unit.suffix) {
				total += time.Duration(value) * unit.size
				text, matched = text[len(unit.suffix):], true
				break
			}
		}
		if !matched {
			return 0, false
		}
	}
	return total, true
}
