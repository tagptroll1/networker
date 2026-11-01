//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	eventExec    = 1
	eventBlocked = 2
	eventSize    = 28
)

// Event is a process exec, or a connection the kernel refused.
type Event struct {
	Blocked  bool
	PID      uint32
	Addr     netip.Addr
	Port     uint16
	Protocol uint8
}

func decodeEvent(sample []byte) (Event, bool) {
	if len(sample) < eventSize {
		return Event{}, false
	}
	event := Event{PID: binary.NativeEndian.Uint32(sample[4:8])}
	switch binary.NativeEndian.Uint32(sample[:4]) {
	case eventExec:
	case eventBlocked:
		event.Blocked = true
		event.Addr = netip.AddrFrom16([16]byte(sample[8:24])).Unmap()
		event.Port = binary.NativeEndian.Uint16(sample[24:26])
		event.Protocol = sample[26]
	default:
		return Event{}, false
	}
	return event, true
}

// ReadEvents delivers kernel policy events until ctx ends.
func (c *Collector) ReadEvents(ctx context.Context, handle func(Event)) error {
	reader, err := ringbuf.NewReader(c.objects.PolicyEvents)
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
		if event, ok := decodeEvent(record.RawSample); ok {
			handle(event)
		}
	}
	return nil
}

// SetEnforcing turns the kernel's block checks on or off.
func (c *Collector) SetEnforcing(on bool) error {
	value := uint32(0)
	if on {
		value = 1
	}
	return c.objects.Enforcing.Put(uint32(0), value)
}

// AssignApp binds a process to a rule app id. Its later children inherit it, and
// an inherited id stays: running another program must not shed the parent's rules.
func (c *Collector) AssignApp(pid, app uint32) error {
	err := c.objects.AppIds.Update(pid, app, ebpf.UpdateNoExist)
	if errors.Is(err, ebpf.ErrKeyExist) {
		return nil
	}
	return err
}

// Block refuses a prefix for one rule app, or for everyone when app is 0.
func (c *Collector) Block(app uint32, prefix netip.Prefix) error {
	return c.objects.Blocks.Put(blockKey(app, prefix), uint8(1))
}

// Unblock removes what Block added.
func (c *Collector) Unblock(app uint32, prefix netip.Prefix) error {
	return c.objects.Blocks.Delete(blockKey(app, prefix))
}

func blockKey(app uint32, prefix netip.Prefix) networkerBlockKey {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		bits += 96
	}
	// The trie matches on app first, then address.
	return networkerBlockKey{Prefixlen: uint32(32 + bits), App: app, Addr: prefix.Masked().Addr().As16()}
}
