package capture

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/asm"
)

func TestEmbeddedPrograms(t *testing.T) {
	spec, err := loadNetworker()
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) != 6 || spec.Maps["flows"] == nil || spec.Maps["owners"] == nil {
		t.Fatalf("unexpected BPF objects: %d programs, %d maps", len(spec.Programs), len(spec.Maps))
	}
	if spec.Maps["flows"].KeySize != 40 || spec.Maps["flows"].ValueSize != 72 {
		t.Fatalf("unexpected flow layout: %+v", spec.Maps["flows"])
	}
	for _, name := range []string{"egress", "ingress"} {
		loads := 0
		for _, instruction := range spec.Programs[name].Instructions {
			if instruction.IsBuiltinCall() && instruction.Constant == int64(asm.FnSkbLoadBytes) {
				loads++
			}
		}
		if loads < 4 {
			t.Errorf("%s: expected checked IP, port, and TCP flag reads, got %d skb loads", name, loads)
		}
	}
	ip, ok := address(4, [16]uint8{1, 2, 3, 4})
	if !ok || ip.String() != "1.2.3.4" {
		t.Fatal("IPv4 address decoded incorrectly")
	}
	ip, ok = address(6, [16]uint8{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if !ok || ip.String() != "2001:db8::1" {
		t.Fatal("IPv6 address decoded incorrectly")
	}
}

func TestProcAddress(t *testing.T) {
	for _, test := range []struct {
		raw    string
		family int
		want   string
	}{
		{"0100007F:346C", 4, "127.0.0.1:13420"},
		{"00000000000000000000000001000000:01BB", 6, "[::1]:443"},
	} {
		addr, ok := procAddress(test.raw, test.family)
		if !ok || addr.String() != test.want {
			t.Fatalf("%s: got %s, %v", test.raw, addr, ok)
		}
	}
}

func TestEnrichInboundAndLoopback(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"net", "123/fd", "456/fd"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	table := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		"0: 0100007F:346C 0100007F:C001 01 00000000:00000000 00:00000000 00000000 0 0 1001\n" +
		"1: 0100007F:C001 0100007F:346C 01 00000000:00000000 00:00000000 00000000 0 0 1002\n"
	if err := os.WriteFile(filepath.Join(root, "net/tcp"), []byte(table), 0600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ path, target string }{
		{"123/fd/5", "socket:[1001]"}, {"456/fd/6", "socket:[1002]"},
		{"123/exe", "/usr/bin/http-client"}, {"456/exe", "/usr/bin/networker"},
	} {
		if err := os.Symlink(item.target, filepath.Join(root, item.path)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "123/cgroup"), []byte("0::/user.slice/user-1000.slice/app.slice/browser.scope\n"), 0600); err != nil {
		t.Fatal(err)
	}
	flows := []Flow{
		{Key: Key{Local: netip.MustParseAddrPort("127.0.0.1:13420"), Remote: netip.MustParseAddrPort("127.0.0.1:49153"), Protocol: 6}, Inbound: true},
		{Key: Key{Local: netip.MustParseAddrPort("127.0.0.1:49153"), Remote: netip.MustParseAddrPort("127.0.0.1:13420"), Protocol: 6}},
	}
	enrich(root, flows)
	if flows[0].PID != 123 || flows[0].App != "http-client" || flows[0].Executable != "/usr/bin/http-client" || flows[0].Unit != "browser.scope" {
		t.Fatalf("server: %+v", flows[0])
	}
	if flows[1].PID != 456 || flows[1].App != "networker" {
		t.Fatalf("client: %+v", flows[1])
	}
}
