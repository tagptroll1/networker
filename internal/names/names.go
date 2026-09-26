package names

import (
	"net/netip"
	"sync"
	"time"

	"github.com/tagptroll1/networker/internal/capture"
)

const maxEntries = 4096

type entry struct {
	name    string
	expires time.Time
}

type Cache struct {
	mu      sync.RWMutex
	entries map[netip.Addr]entry
}

func New() *Cache { return &Cache{entries: make(map[netip.Addr]entry)} }

func (c *Cache) Remember(answers []capture.DNSAnswer, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, answer := range answers {
		if !answer.Address.IsValid() || answer.Name == "" || answer.TTL <= 0 {
			continue
		}
		c.entries[answer.Address.Unmap()] = entry{answer.Name, now.Add(answer.TTL)}
	}
	if len(c.entries) <= maxEntries {
		return
	}
	for ip, item := range c.entries {
		if !item.expires.After(now) {
			delete(c.entries, ip)
		}
	}
	for len(c.entries) > maxEntries {
		var oldest netip.Addr
		var expiry time.Time
		for ip, item := range c.entries {
			if oldest == (netip.Addr{}) || item.expires.Before(expiry) {
				oldest, expiry = ip, item.expires
			}
		}
		delete(c.entries, oldest)
	}
}

func (c *Cache) Lookup(ip netip.Addr) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.entries[ip.Unmap()]
	if !ok || !item.expires.After(time.Now()) {
		return ""
	}
	return item.name
}
