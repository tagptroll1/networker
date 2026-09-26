package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestDNSResponseNames(t *testing.T) {
	response := make([]byte, 12)
	response[2], response[5], response[7] = 0x81, 1, 3
	response = append(response, 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	response = append(response, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 40, 0, 7, 4, 'e', 'd', 'g', 'e', 0xc0, 20)
	response = append(response, 0xc0, 41, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 42)
	response = append(response, 4, 'e', 'v', 'i', 'l', 0, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1)
	answers := parseDNSResponse(response)
	if len(answers) != 1 || answers[0].Name != "example.com" || answers[0].Address.String() != "203.0.113.42" || answers[0].TTL != 30*time.Second {
		t.Fatalf("answers: %+v", answers)
	}
	event := make([]byte, 292)
	event[18], event[19] = 4, 1
	binary.NativeEndian.PutUint16(event[16:18], uint16(len(response)))
	copy(event[20:], response)
	_, decoded, isQuery := decodeDNS(event)
	if isQuery || len(decoded) != 1 || decoded[0] != answers[0] {
		t.Fatalf("decoded: %+v query=%v", decoded, isQuery)
	}
	response[2] = 0x83
	if got := parseDNSResponse(response); len(got) != 0 {
		t.Fatalf("accepted truncated response: %+v", got)
	}
}

func TestDNSResponseIPv6AndMalformedPointer(t *testing.T) {
	response := make([]byte, 12)
	response[2], response[5], response[7] = 0x80, 1, 1
	response = append(response, 1, 'x', 0, 0, 28, 0, 1)
	response = append(response, 0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16)
	ip := netip.MustParseAddr("2001:db8::1").As16()
	response = append(response, ip[:]...)
	answers := parseDNSResponse(response)
	if len(answers) != 1 || answers[0].Name != "x" || answers[0].Address.String() != "2001:db8::1" {
		t.Fatalf("IPv6 answers: %+v", answers)
	}
	response[19] = 0xc0
	response[20] = 19
	if got := parseDNSResponse(response); len(got) != 0 {
		t.Fatalf("accepted malformed pointer: %+v", got)
	}
}
