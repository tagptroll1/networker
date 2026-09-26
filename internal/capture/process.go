//go:build linux

package capture

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// enrich looks up sockets without a connect/sendmsg owner while they still exist.
func enrich(root string, flows []Flow) {
	missing := make(map[Key][]int)
	for i := range flows {
		if flows[i].PID == 0 {
			missing[flows[i].Key] = append(missing[flows[i].Key], i)
		}
	}
	if len(missing) != 0 {
		inodes := make(map[string][]int)
		for _, table := range []struct {
			name     string
			protocol uint8
			family   int
		}{
			{"tcp", 6, 4}, {"tcp6", 6, 6}, {"udp", 17, 4}, {"udp6", 17, 6},
		} {
			f, err := os.Open(filepath.Join(root, "net", table.name))
			if err != nil {
				continue
			}
			scan := bufio.NewScanner(f)
			for scan.Scan() {
				fields := strings.Fields(scan.Text())
				if len(fields) < 10 {
					continue
				}
				local, localOK := procAddress(fields[1], table.family)
				remote, remoteOK := procAddress(fields[2], table.family)
				if !localOK || !remoteOK {
					continue
				}
				key := Key{Local: local, Remote: remote, Protocol: table.protocol}
				if indexes := missing[key]; len(indexes) != 0 && fields[9] != "0" {
					inodes[fields[9]] = append(inodes[fields[9]], indexes...)
				}
			}
			f.Close()
		}
		if len(inodes) != 0 {
			findSocketOwners(root, inodes, flows)
		}
	}
	cache := make(map[uint32]process)
	for i := range flows {
		pid := flows[i].PID
		if pid == 0 {
			continue
		}
		info, ok := cache[pid]
		if !ok {
			info = readProcess(root, pid)
			cache[pid] = info
		}
		flows[i].Executable, flows[i].Unit = info.executable, info.unit
		if info.executable != "" {
			flows[i].App = filepath.Base(info.executable)
		} else if flows[i].App == "" {
			flows[i].App = info.comm
		}
	}
}

func procAddress(raw string, family int) (netip.AddrPort, bool) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return netip.AddrPort{}, false
	}
	width := 8
	if family == 6 {
		width = 32
	}
	if len(parts[0]) != width {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var bytes [16]byte
	for i := 0; i < width/8; i++ {
		word, err := strconv.ParseUint(parts[0][i*8:i*8+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		for j := 0; j < 4; j++ {
			bytes[i*4+j] = byte(word >> (8 * j))
		}
	}
	if family == 4 {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(bytes[:4])), uint16(port)), true
	}
	return netip.AddrPortFrom(netip.AddrFrom16(bytes), uint16(port)), true
}

func findSocketOwners(root string, inodes map[string][]int, flows []Flow) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	owners := make(map[string]uint32)
	ambiguous := make(map[string]bool)
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || pid == 0 || !entry.IsDir() {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(root, entry.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(root, entry.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if len(inodes[inode]) == 0 {
				continue
			}
			if owner := owners[inode]; owner != 0 && owner != uint32(pid) {
				ambiguous[inode] = true
			} else {
				owners[inode] = uint32(pid)
			}
		}
	}
	for inode, indexes := range inodes {
		if ambiguous[inode] {
			continue
		}
		for _, index := range indexes {
			if flows[index].PID == 0 {
				flows[index].PID = owners[inode]
			}
		}
	}
}

type process struct{ executable, unit, comm string }

func readProcess(root string, pid uint32) process {
	dir := filepath.Join(root, fmt.Sprint(pid))
	var info process
	info.executable, _ = os.Readlink(filepath.Join(dir, "exe"))
	if comm, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		info.comm = strings.TrimSpace(string(comm))
	}
	if cgroups, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		for _, line := range strings.Split(string(cgroups), "\n") {
			for _, part := range strings.Split(line, "/") {
				if strings.HasSuffix(part, ".service") || strings.HasSuffix(part, ".scope") {
					info.unit = part
				}
			}
		}
	}
	return info
}
