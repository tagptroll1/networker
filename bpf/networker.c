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

// Prefix bits cover app then address, so one trie holds per-app and everyone
// (app 0) rules. IPv4 is stored IPv4-mapped.
struct block_key {
    __u32 prefixlen;
    __u32 app;
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct block_key);
    __type(value, __u8);
} blocks SEC(".maps");

// Process (tgid) to rule app id. Identity lives here so a forked child is
// covered before its first connect, without waiting on userspace.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} app_ids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} enforcing SEC(".maps");

#define EVENT_EXEC 1
#define EVENT_BLOCKED 2

struct policy_event {
    __u32 kind;
    __u32 pid;
    __u8 addr[16];
    __u16 port;
    __u8 protocol;
    __u8 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} policy_events SEC(".maps");

// Only the fields read; CO-RE resolves their offsets against the running kernel.
struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));

static __always_inline int is_blocked(__u32 pid, const __u8 *addr)
{
    __u32 zero = 0;
    __u32 *on = bpf_map_lookup_elem(&enforcing, &zero);
    if (!on || !*on)
        return 0;
    struct block_key key = { .prefixlen = 160 };
    __builtin_memcpy(key.addr, addr, 16);
    if (bpf_map_lookup_elem(&blocks, &key))
        return 1;
    __u32 *app = bpf_map_lookup_elem(&app_ids, &pid);
    if (!app)
        return 0;
    key.app = *app;
    return bpf_map_lookup_elem(&blocks, &key) != NULL;
}

static __always_inline void report_blocked(__u32 pid, const __u8 *addr, __u16 port, __u8 protocol)
{
    struct policy_event *event = bpf_ringbuf_reserve(&policy_events, sizeof(*event), 0);
    if (!event)
        return;
    event->kind = EVENT_BLOCKED;
    event->pid = pid;
    __builtin_memcpy(event->addr, addr, 16);
    event->port = port;
    event->protocol = protocol;
    event->pad = 0;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void mapped4(__u8 *addr, __u32 ip)
{
    __builtin_memset(addr, 0, 10);
    addr[10] = 0xff;
    addr[11] = 0xff;
    __builtin_memcpy(addr + 12, &ip, 4);
}

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

// 1 lets the call through; 0 fails it with EPERM.
static __always_inline int decide(struct bpf_sock_addr *ctx, const __u8 *addr)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_blocked(pid, addr))
        return 1;
    report_blocked(pid, addr, bpf_ntohs(ctx->user_port), ctx->protocol);
    return 0;
}

static __always_inline int decide4(struct bpf_sock_addr *ctx)
{
    __u8 addr[16];
    mapped4(addr, ctx->user_ip4);
    return decide(ctx, addr);
}

static __always_inline int decide6(struct bpf_sock_addr *ctx)
{
    __u32 words[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3] };
    return decide(ctx, (const __u8 *)words);
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    remember_owner(ctx);
    return decide4(ctx);
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx)
{
    remember_owner(ctx);
    return decide6(ctx);
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx)
{
    remember_owner(ctx);
    return decide4(ctx);
}

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx)
{
    remember_owner(ctx);
    return decide6(ctx);
}

// A child inherits its parent's identity, so an app's helpers stay covered.
SEC("tp_btf/sched_process_fork")
int on_fork(__u64 *ctx)
{
    struct task_struct *parent = (void *)ctx[0];
    struct task_struct *child = (void *)ctx[1];
    __u32 child_id = child->pid;
    // Threads share their process's entry.
    if (child->pid != child->tgid)
        return 0;
    __u32 parent_id = parent->tgid;
    __u32 *app = bpf_map_lookup_elem(&app_ids, &parent_id);
    if (app)
        bpf_map_update_elem(&app_ids, &child_id, app, BPF_ANY);
    else
        bpf_map_delete_elem(&app_ids, &child_id);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int on_exit(__u64 *ctx)
{
    struct task_struct *task = (void *)ctx[0];
    __u32 id = task->pid;
    if (task->pid == task->tgid)
        bpf_map_delete_elem(&app_ids, &id);
    return 0;
}

// Userspace identifies the new program from /proc.
SEC("tp_btf/sched_process_exec")
int on_exec(__u64 *ctx)
{
    struct task_struct *task = (void *)ctx[0];
    struct policy_event *event = bpf_ringbuf_reserve(&policy_events, sizeof(*event), 0);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->kind = EVENT_EXEC;
    event->pid = task->tgid;
    bpf_ringbuf_submit(event, 0);
    return 0;
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

    // connect() alone is not enough: a block learned from a DNS answer can land
    // just after the SYN left, and older sockets never connect again.
    if (outbound) {
        __u64 socket = bpf_get_socket_cookie(skb);
        struct owner *sender = socket ? bpf_map_lookup_elem(&owners, &socket) : NULL;
        __u32 pid = sender ? sender->pid : 0;
        __u8 addr[16];
        if (key.family == 4) {
            __u32 remote;
            __builtin_memcpy(&remote, key.remote, 4);
            mapped4(addr, remote);
        } else {
            __builtin_memcpy(addr, key.remote, 16);
        }
        if (is_blocked(pid, addr)) {
            report_blocked(pid, addr, dest, proto);
            return 0;
        }
    }

    if (proto == 17 && ((outbound && dest == 53) || (!outbound && source == 53))) {
        __u32 size = skb->len - offset - 8;
        if (size > 272)
            size = 272;
        // The verifier needs a direct nonzero bound on the variable-length read.
        if (size >= 12 && size <= skb->len) {
            struct dns_event *event = bpf_ringbuf_reserve(&dns_queries, sizeof(*event), 0);
            if (event) {
                __builtin_memcpy(event->server, key.remote, 16);
                event->family = key.family;
                event->response = !outbound;
                event->size = size;
                if (bpf_skb_load_bytes(skb, offset + 8, event->data, size) == 0)
                    bpf_ringbuf_submit(event, 0);
                else
                    bpf_ringbuf_discard(event, 0);
            }
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
