package names

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tagptroll1/networker/internal/capture"
)

func TestNamesExpireAndBounded(t *testing.T) {
	cache := New()
	ip := netip.MustParseAddr("203.0.113.42")
	cache.Remember([]capture.DNSAnswer{{Name: "example.com", Address: ip, TTL: time.Minute}}, time.Now())
	if got := cache.Lookup(ip); got != "example.com" {
		t.Fatalf("lookup: %q", got)
	}
	cache.Remember([]capture.DNSAnswer{{Name: "expired.test", Address: ip, TTL: time.Second}}, time.Now().Add(-2*time.Second))
	if got := cache.Lookup(ip); got != "" {
		t.Fatalf("expired lookup: %q", got)
	}
	answers := make([]capture.DNSAnswer, 0, maxEntries+1)
	for i := 0; i <= maxEntries; i++ {
		answers = append(answers, capture.DNSAnswer{Name: "bulk.test", Address: netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), TTL: time.Minute})
	}
	cache.Remember(answers, time.Now())
	if len(cache.entries) != maxEntries {
		t.Fatalf("cache size: %d", len(cache.entries))
	}
}
