// filemon.bpf.c — hooks the openat() syscall entry and streams a file-access
// event to userspace via a ring buffer.
//
// To keep the stream useful rather than overwhelming, we deliberately only
// emit an event when the open() requests *write* access (any of the write-ish
// flags below) OR the path lives under /etc/. Logging every read open() on a
// busy system would bury the signal. Deciding which specific /etc/ paths are
// actually sensitive (e.g. /etc/shadow vs /etc/foo) is the rule engine's job
// in a later step — this monitor stays dumb on purpose.
//
// We avoid libc's <fcntl.h> (it conflicts when targeting bpf) and hand-define
// the O_* flag bits as plain macros instead.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// open() flag bits (x86_64 asm-generic values). Hand-defined to avoid pulling
// in libc's <fcntl.h>, which breaks the bpf target.
#define O_WRONLY 00000001
#define O_RDWR   00000002
#define O_CREAT  00000100
#define O_TRUNC  00001000
#define O_APPEND 00002000

// Event streamed to userspace. Keep this layout in sync with the Go side;
// bpf2go regenerates the matching Go struct (filemonEvent) from this BTF.
struct event {
	__u32 pid;
	__u32 flags;
	__u64 cgroup_id;
	__u8 comm[16];
	__u8 filename[256];
};

// Force bpf2go's BTF type generation to emit `struct event`. Unused otherwise.
struct event *unused_event __attribute__((unused));

// Generic context shared by every syscalls:sys_enter_* tracepoint: the common
// 8-byte header, the syscall id, then the raw syscall arguments. For openat the
// args are (dfd, filename, flags, mode), so args[1] is the filename pointer and
// args[2] is the flags.
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

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;

	// Reserve the ring buffer slot up front and read the filename straight
	// into it. The BPF stack is capped at 512 bytes, so we avoid staging the
	// 256-byte path in a separate stack buffer — we reuse this reserved space.
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	const char *filename = (const char *)ctx->args[1];
	__u32 flags = (__u32)ctx->args[2];

	// openat's filename is a *userspace* pointer; use the _user variant.
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	// Noise filter: keep writes (any path) and reads under /etc/, drop the rest.
	int is_write = flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND);
	int is_etc = e->filename[0] == '/' && e->filename[1] == 'e' &&
		     e->filename[2] == 't' && e->filename[3] == 'c' &&
		     e->filename[4] == '/';
	if (!is_write && !is_etc) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32; // tgid (userspace PID)
	e->flags = flags;
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
