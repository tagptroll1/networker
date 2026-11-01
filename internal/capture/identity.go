//go:build linux

package capture

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Runtimes host other programs, so their binary name says nothing about the app.
var runtimes = regexp.MustCompile(`^(electron|node|bun|deno|python[0-9.]*|java|ruby|perl|dotnet|mono)$`)

var (
	storePath   = regexp.MustCompile(`^/nix/store/[a-z0-9]{32}-([^/]+)`)
	nameVersion = regexp.MustCompile(`-[0-9].*$`)
	// Entry points named for their role rather than the app they belong to.
	genericEntry = map[string]bool{"app": true, "main": true, "index": true, "__main__": true, "cli": true, "server": true}
)

// Identify names the app a process belongs to, stable across updates and shared
// runtimes: Electron apps all run the same binary, and their network process
// has no app path in its arguments, so helpers defer to their parent. This is
// for attribution, not proof: a process controls its own arguments.
func Identify(root string, pid uint32) string {
	first := ""
	for depth := 0; depth < 16 && pid > 1; depth++ {
		dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))
		exe, err := os.Readlink(filepath.Join(dir, "exe"))
		if err != nil {
			break
		}
		name := binaryName(exe)
		if first == "" {
			first = name
		}
		if !runtimes.MatchString(name) {
			if depth == 0 {
				return name
			}
			break
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		// Electron rewrites its arguments into one space-joined string.
		if len(args) == 1 {
			args = strings.Fields(args[0])
		}
		if entry := scriptName(args); entry != "" {
			return entry
		}
		pid = parentPID(dir)
	}
	return first
}

// Processes lists every running process.
func Processes(root string) []uint32 {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	pids := make([]uint32, 0, len(entries))
	for _, entry := range entries {
		if pid, err := strconv.ParseUint(entry.Name(), 10, 32); err == nil && pid != 0 {
			pids = append(pids, uint32(pid))
		}
	}
	return pids
}

func binaryName(exe string) string {
	name := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	// Nix wrappers leave the real binary as .name-wrapped.
	for strings.HasPrefix(name, ".") && strings.HasSuffix(name, "-wrapped") {
		name = strings.TrimSuffix(strings.TrimPrefix(name, "."), "-wrapped")
	}
	return name
}

func scriptName(args []string) string {
	for _, arg := range args[min(1, len(args)):] {
		// Chromium-style helpers carry no entry point of their own.
		if strings.HasPrefix(arg, "--type=") {
			return ""
		}
	}
	for _, arg := range args[min(1, len(args)):] {
		if arg == "" || strings.HasPrefix(arg, "-") || strings.ContainsAny(arg, " \t\n") {
			continue
		}
		if match := storePath.FindStringSubmatch(arg); match != nil {
			return nameVersion.ReplaceAllString(match[1], "")
		}
		base := filepath.Base(arg)
		entry := strings.TrimSuffix(base, filepath.Ext(base))
		if genericEntry[entry] {
			if parent := filepath.Base(filepath.Dir(arg)); parent != "." && parent != "/" {
				return parent
			}
		}
		return entry
	}
	return ""
}

func parentPID(dir string) uint32 {
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return 0
	}
	// comm can hold spaces and parentheses, so fields count from the last ')'.
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return 0
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 2 {
		return 0
	}
	parent, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(parent)
}
