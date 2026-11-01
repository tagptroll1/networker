package capture

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hash = "abcdefghijklmnopqrstuvwxyz012345"

func fakeProcess(t *testing.T, root string, pid, parent int, exe string, args ...string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(args, "\x00")+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (odd) name) S %d 0 0", pid, parent)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIdentify(t *testing.T) {
	root := t.TempDir()
	electron := "/nix/store/" + hash + "-electron-unwrapped-44/libexec/electron/electron"
	asar := "/nix/store/" + hash + "-freetube-0.25.3/share/freetube/resources/app.asar"
	fakeProcess(t, root, 2, 1, "/bin/bash", "bash")
	fakeProcess(t, root, 10, 2, electron, "electron", "--ozone-platform-hint=auto", asar)
	fakeProcess(t, root, 11, 10, electron, "electron", "--type=utility", "--utility-sub-type=network.mojom.NetworkService")
	fakeProcess(t, root, 12, 11, electron, "electron", "--type=renderer", "--app-path="+asar)
	fakeProcess(t, root, 20, 2, electron, "electron", "--type=utility")
	fakeProcess(t, root, 30, 2, "/nix/store/"+hash+"-curl/bin/curl", "curl", "https://example.com")
	fakeProcess(t, root, 31, 2, "/nix/store/"+hash+"-x/bin/.slack-wrapped", "slack")
	fakeProcess(t, root, 32, 2, "/usr/bin/python3.12", "python3", "/opt/backup/sync.py")
	fakeProcess(t, root, 33, 2, "/usr/bin/node", "node", "/opt/tool/index.js")
	fakeProcess(t, root, 34, 2, "/usr/bin/python3", "python3", "-c", "print(1) ; print(2)")
	fakeProcess(t, root, 35, 2, "/usr/lib/thing (deleted)", "thing")
	// As Electron really reports itself: one string, flags before the app path.
	vesktop := "/nix/store/" + hash + "-vesktop-1.6.8/opt/Vesktop/resources/app.asar"
	fakeProcess(t, root, 40, 2, electron, electron+" --enable-speech-dispatcher --ozone-platform-hint=auto "+vesktop)
	fakeProcess(t, root, 41, 40, electron, electron+" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US")
	for pid, want := range map[uint32]string{
		10: "freetube", 11: "freetube", 12: "freetube", // helpers resolve to their app
		20: "electron", // no parent to defer to
		40: "vesktop", 41: "vesktop",
		30: "curl", 31: "slack", 32: "sync", 33: "tool", 34: "python3", 35: "thing",
		99: "",
	} {
		if got := Identify(root, pid); got != want {
			t.Errorf("pid %d: got %q, want %q", pid, got, want)
		}
	}
	if pids := Processes(root); len(pids) != 13 {
		t.Errorf("Processes: %v", pids)
	}
}

func TestBlockKey(t *testing.T) {
	v4 := blockKey(7, netip.MustParsePrefix("1.2.3.4/24"))
	if v4.Prefixlen != 32+96+24 || v4.App != 7 || v4.Addr != netip.MustParseAddr("::ffff:1.2.3.0").As16() {
		t.Errorf("IPv4 prefix: %+v", v4)
	}
	if v6 := blockKey(0, netip.MustParsePrefix("2001:db8::/32")); v6.Prefixlen != 64 {
		t.Errorf("IPv6 prefix: %+v", v6)
	}
}

func TestDecodeEvent(t *testing.T) {
	sample := make([]byte, eventSize)
	sample[0] = eventBlocked
	sample[4] = 42
	addr := netip.MustParseAddr("::ffff:1.2.3.4").As16()
	copy(sample[8:], addr[:])
	sample[24] = 80
	sample[26] = 6
	event, ok := decodeEvent(sample)
	if !ok || !event.Blocked || event.PID != 42 || event.Addr != netip.MustParseAddr("1.2.3.4") || event.Port != 80 || event.Protocol != 6 {
		t.Fatalf("decoded %+v, %v", event, ok)
	}
	sample[0] = eventExec
	if event, ok = decodeEvent(sample); !ok || event.Blocked {
		t.Fatalf("exec decoded %+v, %v", event, ok)
	}
	sample[0] = 9
	if _, ok = decodeEvent(sample); ok {
		t.Fatal("unknown kind accepted")
	}
	if _, ok = decodeEvent(sample[:4]); ok {
		t.Fatal("short sample accepted")
	}
}
