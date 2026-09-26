#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __u8 local[16];
    __u8 remote[16];
    __u16 local_port;
    __u16 remote_port;
    __u8 family;
    __u8 protocol;
    __u16 pad;
};

struct flow_value {
    __u64 first_ns;
    __u64 last_ns;
    __u64 sent;
    __u64 received;
    __u64 cookie;
    __u32 pid;
    __u64 flags;
    char comm[16];
};

struct owner {
    __u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct owner);
} owners SEC(".maps");

struct dns_event {
    __u8 server[16];
    __u16 size;
    __u8 family;
    __u8 response;
    __u8 data[272];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} dns_queries SEC(".maps");

static __always_inline void remember_owner(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie)
        return;
    struct owner value = {};
    value.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(value.comm, sizeof(value.comm));
    bpf_map_update_elem(&owners, &cookie, &value, BPF_ANY);
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    remember_owner(ctx);
    return 1;
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx)
{
    remember_owner(ctx);
    return 1;
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx)
{
    remember_owner(ctx);
    return 1;
}

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx)
{
    remember_owner(ctx);
    return 1;
}

static __always_inline int account(struct __sk_buff *skb, int outbound)
{
    __u8 ip[20];
    if (bpf_skb_load_bytes(skb, 0, ip, sizeof(ip)) < 0)
        return 1;
    struct flow_key key = {};
    __u32 offset;
    __u8 proto;

    if ((ip[0] >> 4) == 4) {
        offset = (ip[0] & 15) * 4;
        if (offset < 20)
            return 1;
        // Non-initial fragments have no transport header.
        if ((ip[6] & 0x1f) || ip[7])
            return 1;
        proto = ip[9];
        key.family = 4;
        __builtin_memcpy(outbound ? key.local : key.remote, ip + 12, 4);
        __builtin_memcpy(outbound ? key.remote : key.local, ip + 16, 4);
    } else if ((ip[0] >> 4) == 6) {
        __u8 ip6[40];
        if (bpf_skb_load_bytes(skb, 0, ip6, sizeof(ip6)) < 0)
            return 1;
        // Extension headers need separate parsing; never misread their bytes as ports.
        proto = ip6[6];
        offset = 40;
        key.family = 6;
        __builtin_memcpy(outbound ? key.local : key.remote, ip6 + 8, 16);
        __builtin_memcpy(outbound ? key.remote : key.local, ip6 + 24, 16);
    } else {
        return 1;
    }
    if (proto != 6 && proto != 17)
        return 1;
    key.protocol = proto;
    __u8 ports[4];
    if (bpf_skb_load_bytes(skb, offset, ports, sizeof(ports)) < 0)
        return 1;
    __u16 source = ((__u16)ports[0] << 8) | ports[1];
    __u16 dest = ((__u16)ports[2] << 8) | ports[3];
    key.local_port = outbound ? source : dest;
    key.remote_port = outbound ? dest : source;

    if (proto == 17 && ((outbound && dest == 53) || (!outbound && source == 53))) {
        struct dns_event event = {};
        __u32 size = skb->len - offset - 8;
        if (size > sizeof(event.data))
            size = sizeof(event.data);
        // The verifier needs a direct nonzero bound on the variable-length read.
        if (size >= 12 && size <= skb->len) {
            __builtin_memcpy(event.server, key.remote, 16);
            event.family = key.family;
            event.response = !outbound;
            event.size = size;
            if (bpf_skb_load_bytes(skb, offset + 8, event.data, size) == 0)
                bpf_ringbuf_output(&dns_queries, &event, sizeof(event), 0);
        }
    }

    __u64 now = bpf_ktime_get_ns();
    struct flow_value initial = { .first_ns = now, .last_ns = now, .flags = outbound ? 0 : 8 };
    bpf_map_update_elem(&flows, &key, &initial, BPF_NOEXIST);
    struct flow_value *value = bpf_map_lookup_elem(&flows, &key);
    if (!value)
        return 1;
    value->last_ns = now;
    if (outbound) {
        __u64 cookie = bpf_get_socket_cookie(skb);
        if (cookie && cookie != value->cookie) {
            if (value->cookie) {
                // A different socket reused the same ports; do not inherit its readiness.
                value->first_ns = now;
                value->sent = 0;
                value->received = 0;
                value->flags = 0;
            }
            struct owner *owner = bpf_map_lookup_elem(&owners, &cookie);
            if (owner) {
                value->pid = owner->pid;
                __builtin_memcpy(value->comm, owner->comm, 16);
            } else {
                value->pid = 0;
                __builtin_memset(value->comm, 0, 16);
            }
        }
        if (cookie)
            value->cookie = cookie;
        __sync_fetch_and_add(&value->sent, skb->len);
        if (proto == 17) {
            __sync_fetch_and_or(&value->flags, 4);
        } else {
            __u8 tcp_flags;
            if (bpf_skb_load_bytes(skb, offset + 13, &tcp_flags, sizeof(tcp_flags)) < 0)
                return 1;
            if (tcp_flags & 2)
                __sync_fetch_and_or(&value->flags, 1); // outgoing SYN
            else if (tcp_flags & 16)
                __sync_fetch_and_or(&value->flags, 4); // ACK, not failed SYN
        }
    } else {
        __sync_fetch_and_add(&value->received, skb->len);
        if (proto == 17) {
            __sync_fetch_and_or(&value->flags, 4);
        } else {
            __u8 tcp_flags;
            if (bpf_skb_load_bytes(skb, offset + 13, &tcp_flags, sizeof(tcp_flags)) < 0)
                return 1;
            if ((tcp_flags & 18) == 18)
                __sync_fetch_and_or(&value->flags, 2); // received SYN-ACK
            else if ((value->flags & 8) && (tcp_flags & 16) && !(tcp_flags & 2))
                __sync_fetch_and_or(&value->flags, 4); // inbound socket exchanged ACK
        }
    }
    return 1;
}

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
    return account(skb, 1);
}

SEC("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb)
{
    return account(skb, 0);
}

char LICENSE[] SEC("license") = "GPL";
