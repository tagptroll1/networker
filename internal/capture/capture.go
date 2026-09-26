//go:build linux

package capture

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Key struct {
	Local, Remote netip.AddrPort
	Protocol      uint8
}

type Flow struct {
	Key             Key
	Sent, Received  uint64
	FirstNS, LastNS uint64
	Cookie          uint64
	PID             uint32
	App             string
	Executable      string
	Unit            string
	Ready           bool
	Inbound         bool
	Established     bool
}

type Collector struct {
	objects networkerObjects
	links   []link.Link
}

func Open() (_ *Collector, err error) {
	c := &Collector{}
	if err := loadNetworkerObjects(&c.objects, nil); err != nil {
		return nil, fmt.Errorf("load eBPF programs (requires BPF privileges): %w", err)
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	hooks := []struct {
		name    string
		program *ebpf.Program
		attach  ebpf.AttachType
	}{
		{"IPv4 connect", c.objects.Connect4, ebpf.AttachCGroupInet4Connect},
		{"IPv6 connect", c.objects.Connect6, ebpf.AttachCGroupInet6Connect},
		{"IPv4 UDP send", c.objects.Sendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{"IPv6 UDP send", c.objects.Sendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
		{"outbound packets", c.objects.Egress, ebpf.AttachCGroupInetEgress},
		{"inbound packets", c.objects.Ingress, ebpf.AttachCGroupInetIngress},
	}
	for _, hook := range hooks {
		l, attachErr := link.AttachCgroup(link.CgroupOptions{Path: "/sys/fs/cgroup", Attach: hook.attach, Program: hook.program})
		if attachErr != nil {
			return nil, fmt.Errorf("attach %s: %w", hook.name, attachErr)
		}
		c.links = append(c.links, l)
	}
	return c, nil
}

func (c *Collector) Close() error {
	var errs []error
	for _, l := range c.links {
		errs = append(errs, l.Close())
	}
	errs = append(errs, c.objects.Close())
	return errors.Join(errs...)
}

func (c *Collector) Snapshot() ([]Flow, error) {
	result := make([]Flow, 0)
	var key networkerFlowKey
	var value networkerFlowValue
	it := c.objects.Flows.Iterate()
	for it.Next(&key, &value) {
		local, ok := address(key.Family, key.Local)
		if !ok {
			continue
		}
		remote, ok := address(key.Family, key.Remote)
		if !ok {
			continue
		}
		comm := make([]byte, 0, len(value.Comm))
		for _, b := range value.Comm {
			if b == 0 {
				break
			}
			comm = append(comm, byte(b))
		}
		result = append(result, Flow{
			Key:  Key{netip.AddrPortFrom(local, key.LocalPort), netip.AddrPortFrom(remote, key.RemotePort), key.Protocol},
			Sent: value.Sent, Received: value.Received, FirstNS: value.FirstNs, LastNS: value.LastNs,
			Cookie: value.Cookie, PID: value.Pid, App: string(comm), Ready: value.Flags&4 != 0,
			Inbound: value.Flags&8 != 0, Established: value.Flags&3 == 3,
		})
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	enrich("/proc", result)
	return result, nil
}

func address(family uint8, raw [16]uint8) (netip.Addr, bool) {
	switch family {
	case 4:
		return netip.AddrFrom4([4]byte(raw[:4])), true
	case 6:
		return netip.AddrFrom16(raw), true
	default:
		return netip.Addr{}, false
	}
}
