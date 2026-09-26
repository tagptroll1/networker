package capture

import (
	"encoding/binary"
	"testing"
)

func TestParseDNS(t *testing.T) {
	packet := make([]byte, 12)
	packet[5] = 1
	packet = append(packet, 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 28, 0, 1)
	name, kind, ok := parseDNS(packet)
	if !ok || name != "example.com" || kind != "AAAA" {
		t.Fatalf("query: %q %q %v", name, kind, ok)
	}
	for _, bad := range [][]byte{
		packet[:len(packet)-1],
		append([]byte(nil), packet[:12]...),
		append(append([]byte(nil), packet[:12]...), 0xc0, 12, 0, 1, 0, 1),
	} {
		if _, _, ok := parseDNS(bad); ok {
			t.Fatalf("accepted malformed query: %x", bad)
		}
	}
	response := append([]byte(nil), packet...)
	response[2] = 0x80
	if _, _, ok := parseDNS(response); ok {
		t.Fatal("accepted DNS response")
	}
	event := make([]byte, 292)
	event[0], event[1], event[2], event[3] = 127, 0, 0, 53
	event[18] = 4
	binary.NativeEndian.PutUint16(event[16:18], uint16(len(packet)))
	copy(event[20:], packet)
	query, _, ok := decodeDNS(event)
	if !ok || query.Name != "example.com" || query.Type != "AAAA" || query.ServerIP.String() != "127.0.0.53" {
		t.Fatalf("event: %+v %v", query, ok)
	}
}
