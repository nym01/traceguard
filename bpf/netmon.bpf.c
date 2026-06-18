// netmon.bpf.c — hooks the connect() syscall entry and streams an outbound
// connection event to userspace via a ring buffer.
//
// This is the core signal for reverse shells, C2 beaconing, and data
// exfiltration. We fire on every connect() *attempt*, not just successful
// ones — a failed/refused connect (e.g. probing a dead C2 server) is still
// security-relevant. Unlike the file monitor, no noise filter is needed:
// outbound connects are naturally far lower volume than file opens or execs.
//
// v1 scope is IPv4 (AF_INET) only. AF_INET6/AF_UNIX are silently skipped by
// bailing out after the sin_family check.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // bpf_ntohs

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2

// Event streamed to userspace. Keep this layout in sync with the Go side;
// bpf2go regenerates the matching Go struct (netmonEvent) from this BTF.
// dst_ip is a raw 4-byte array (NOT a __u32) so it preserves dotted-quad byte
// order with zero ambiguity on the Go side; dst_port is converted to host byte
// order in-kernel (bpf_ntohs) so Go can print it as a plain integer.
struct event {
	__u32 pid;
	__u64 cgroup_id;
	__u16 dst_port;
	__u8 dst_ip[4];
	__u8 comm[16];
};

// Force bpf2go's BTF type generation to emit `struct event`. Unused otherwise.
struct event *unused_event __attribute__((unused));

// Minimal sockaddr_in — deliberately just the first 8 bytes (we omit the
// trailing padding of the real struct). We only bpf_probe_read_user these 8
// bytes from the userspace sockaddr connect() was handed.
struct sockaddr_in {
	unsigned short sin_family;
	unsigned short sin_port;
	unsigned char sin_addr[4];
};

// Generic context shared by every syscalls:sys_enter_* tracepoint: the common
// 8-byte header, the syscall id, then the raw syscall arguments. For connect
// the args are (fd, addr, addrlen), so args[1] is the sockaddr pointer.
struct trace_event_raw_sys_enter {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	__s64 id;
	__u64 args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Counts events dropped because bpf_ringbuf_reserve() failed (ring buffer
// full). A PERCPU_ARRAY gives each CPU its own slot, so the increment below
// needs no atomics; userspace sums the per-CPU values when reporting.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int on_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct sockaddr_in addr;

	// connect's 2nd arg is a *userspace* sockaddr pointer; read the first 8
	// bytes (our trimmed sockaddr_in) and bail out early if we can't read it
	// or it isn't IPv4.
	void *addr_ptr = (void *)ctx->args[1];
	if (bpf_probe_read_user(&addr, sizeof(addr), addr_ptr))
		return 0;
	if (addr.sin_family != AF_INET)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 key = 0;
		__u64 *count = bpf_map_lookup_elem(&dropped_events, &key);
		if (count)
			(*count)++;
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32; // tgid (userspace PID)
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->dst_port = bpf_ntohs(addr.sin_port);
	__builtin_memcpy(e->dst_ip, addr.sin_addr, sizeof(e->dst_ip));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
