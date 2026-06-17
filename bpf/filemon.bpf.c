// filemon.bpf.c — hooks the openat() syscall entry and streams a file-access
// event to userspace via a ring buffer.
//
// To keep the stream useful rather than overwhelming, we deliberately only
// emit an event when the open() requests *write* access (any of the write-ish
// flags below), OR the path lives under /etc/, OR the path carries a sensitive
// credential marker (.ssh/, .aws/, .pem, id_rsa, id_ed25519). The first two
// cover privesc writes and the classic /etc/ secrets; the marker check exists
// because read-opens of credentials living *outside* /etc/ — SSH keys and
// cloud creds in a home dir — would otherwise be dropped here before the rule
// engine ever saw them (a real evasion the validation suite surfaced).
//
// This stays a *coarse* pre-filter: it forwards anything plausibly sensitive
// and leaves the precise decision (which exact path/substring matters) to the
// rule engine. Logging every read open() on a busy system would bury the
// signal, so unmarked reads are still dropped in-kernel.
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

// has_sensitive_marker scans the path for any credential marker substring at
// an arbitrary offset (e.g. /home/u/.ssh/id_rsa, /root/.aws/credentials,
// server.pem). Every index is masked to [0,255] so the verifier can prove the
// access is in-bounds, and the outer loop is bounded by a constant; the scan
// stops early at the NUL terminator. This is a coarse prefix match — it only
// needs to avoid dropping anything the rule engine would later match.
static __always_inline int has_sensitive_marker(const __u8 *f)
{
	for (int i = 0; i < 248; i++) {
		__u8 c0 = f[i & 0xff];
		if (c0 == 0)
			break;
		__u8 c1 = f[(i + 1) & 0xff];
		__u8 c2 = f[(i + 2) & 0xff];
		__u8 c3 = f[(i + 3) & 0xff];
		__u8 c4 = f[(i + 4) & 0xff];

		// ".pem"
		if (c0 == '.' && c1 == 'p' && c2 == 'e' && c3 == 'm')
			return 1;
		// ".ssh/"
		if (c0 == '.' && c1 == 's' && c2 == 's' && c3 == 'h' && c4 == '/')
			return 1;
		// ".aws/"
		if (c0 == '.' && c1 == 'a' && c2 == 'w' && c3 == 's' && c4 == '/')
			return 1;
		// "id_rsa"
		if (c0 == 'i' && c1 == 'd' && c2 == '_' && c3 == 'r' && c4 == 's' &&
		    f[(i + 5) & 0xff] == 'a')
			return 1;
		// "id_ed25519" — the "id_ed" prefix is specific enough to forward on.
		if (c0 == 'i' && c1 == 'd' && c2 == '_' && c3 == 'e' && c4 == 'd')
			return 1;
	}
	return 0;
}

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

	// Noise filter: keep writes (any path), reads under /etc/, and reads of
	// credential-marked paths; drop the rest.
	int is_write = flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND);
	int is_etc = e->filename[0] == '/' && e->filename[1] == 'e' &&
		     e->filename[2] == 't' && e->filename[3] == 'c' &&
		     e->filename[4] == '/';
	if (!is_write && !is_etc && !has_sensitive_marker(e->filename)) {
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
