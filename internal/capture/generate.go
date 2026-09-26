package capture

// BPF_CFLAGS supplies extra include paths per distro; see README "eBPF objects".
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "$BPF_CFLAGS" networker ../../bpf/networker.c
