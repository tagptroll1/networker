//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

type DNSQuery struct {
	Name     string
	Type     string
	ServerIP netip.Addr
}

type DNSAnswer struct {
	Name    string
	Address netip.Addr
	TTL     time.Duration
}

func parseDNS(data []byte) (string, string, bool) {
	if len(data) < 17 || data[2]&0xf8 != 0 || binary.BigEndian.Uint16(data[4:6]) != 1 {
		return "", "", false
	}
	parts := make([]string, 0, 4)
	i := 12
	length := 0
	for {
		if i >= len(data) {
			return "", "", false
		}
		n := int(data[i])
		i++
		if n == 0 {
			break
		}
		if n > 63 || i+n > len(data) || length+n+1 > 253 {
			return "", "", false
		}
		for _, c := range data[i : i+n] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", "", false
			}
		}
		parts = append(parts, string(data[i:i+n]))
		length += n + 1
		i += n
	}
	if len(parts) == 0 || i+4 > len(data) || binary.BigEndian.Uint16(data[i+2:i+4]) != 1 {
		return "", "", false
	}
	qtype := binary.BigEndian.Uint16(data[i : i+2])
	types := map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
	kind := types[qtype]
	if kind == "" {
		kind = fmt.Sprintf("TYPE%d", qtype)
	}
	return strings.ToLower(strings.Join(parts, ".")), kind, true
}

func decodeDNS(sample []byte) (DNSQuery, []DNSAnswer, bool) {
	const header = 20
	if len(sample) < header+272 {
		return DNSQuery{}, nil, false
	}
	size := int(binary.NativeEndian.Uint16(sample[16:18]))
	if size > 272 {
		return DNSQuery{}, nil, false
	}
	var ip netip.Addr
	switch sample[18] {
	case 4:
		ip = netip.AddrFrom4([4]byte(sample[:4]))
	case 6:
		ip = netip.AddrFrom16([16]byte(sample[:16]))
	default:
		return DNSQuery{}, nil, false
	}
	if sample[19] == 1 {
		return DNSQuery{}, parseDNSResponse(sample[header : header+size]), false
	}
	if sample[19] != 0 {
		return DNSQuery{}, nil, false
	}
	name, kind, ok := parseDNS(sample[header : header+size])
	return DNSQuery{Name: name, Type: kind, ServerIP: ip}, nil, ok
}

func dnsName(data []byte, start int) (string, int, bool) {
	parts := make([]string, 0, 4)
	pos, end, length := start, -1, 0
	for hops := 0; hops < 32; hops++ {
		if pos >= len(data) {
			return "", 0, false
		}
		n := int(data[pos])
		pos++
		if n == 0 {
			if end < 0 {
				end = pos
			}
			return strings.ToLower(strings.Join(parts, ".")), end, len(parts) > 0
		}
		if n&0xc0 == 0xc0 {
			if pos >= len(data) {
				return "", 0, false
			}
			if end < 0 {
				end = pos + 1
			}
			pointer := (n&0x3f)<<8 | int(data[pos])
			if pointer >= pos-1 {
				return "", 0, false
			}
			pos = pointer
			continue
		}
		if n > 63 || pos+n > len(data) || length+n+1 > 253 {
			return "", 0, false
		}
		for _, c := range data[pos : pos+n] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", 0, false
			}
		}
		parts = append(parts, string(data[pos:pos+n]))
		length += n + 1
		pos += n
	}
	return "", 0, false
}

func parseDNSResponse(data []byte) []DNSAnswer {
	if len(data) < 12 || data[2]&0xfa != 0x80 || data[3]&0x0f != 0 || binary.BigEndian.Uint16(data[4:6]) != 1 {
		return nil
	}
	question, pos, ok := dnsName(data, 12)
	if !ok || pos+4 > len(data) || binary.BigEndian.Uint16(data[pos+2:pos+4]) != 1 {
		return nil
	}
	pos += 4
	type record struct {
		owner, target string
		address       netip.Addr
		ttl           time.Duration
	}
	var records []record
	for i := 0; i < int(binary.BigEndian.Uint16(data[6:8])); i++ {
		owner, next, ok := dnsName(data, pos)
		if !ok || next+10 > len(data) {
			break
		}
		kind := binary.BigEndian.Uint16(data[next : next+2])
		class := binary.BigEndian.Uint16(data[next+2 : next+4])
		ttl := time.Duration(binary.BigEndian.Uint32(data[next+4:next+8])) * time.Second
		length := int(binary.BigEndian.Uint16(data[next+8 : next+10]))
		pos = next + 10
		if pos+length > len(data) {
			break
		}
		if class == 1 && ttl > 0 {
			r := record{owner: owner, ttl: min(ttl, time.Hour)}
			switch {
			case kind == 1 && length == 4, kind == 28 && length == 16:
				r.address, _ = netip.AddrFromSlice(data[pos : pos+length])
			case kind == 5:
				r.target, next, ok = dnsName(data, pos)
				if !ok || next != pos+length {
					r.target = ""
				}
			}
			if r.address.IsValid() || r.target != "" {
				records = append(records, r)
			}
		}
		pos += length
	}
	var answers []DNSAnswer
	for _, r := range records {
		if !r.address.IsValid() {
			continue
		}
		name, ttl := question, r.ttl
		for hops := 0; hops <= len(records); hops++ {
			if name == r.owner {
				answers = append(answers, DNSAnswer{Name: question, Address: r.address, TTL: ttl})
				break
			}
			found := false
			for _, alias := range records {
				if alias.owner == name && alias.target != "" {
					name, ttl = alias.target, min(ttl, alias.ttl)
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
	}
	return answers
}

// ReadDNS processes observed DNS questions without keeping packet payloads.
func (c *Collector) ReadDNS(ctx context.Context, save func(context.Context, DNSQuery, time.Time) error, remember func([]DNSAnswer, time.Time)) error {
	reader, err := ringbuf.NewReader(c.objects.DnsQueries)
	if err != nil {
		return err
	}
	defer reader.Close()
	for ctx.Err() == nil {
		reader.SetDeadline(time.Now().Add(time.Second))
		record, err := reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return err
		}
		query, answers, ok := decodeDNS(record.RawSample)
		if len(answers) > 0 {
			remember(answers, time.Now())
		}
		if ok {
			if err := save(ctx, query, time.Now()); err != nil && ctx.Err() == nil {
				return err
			}
		}
	}
	return nil
}
