// execmon.bpf.c — hooks sched_process_exec and streams one event per
// successful execve/execveat to userspace via a ring buffer.
//
// We deliberately avoid a bpftool-generated vmlinux.h. Instead we hand-declare
// the tracepoint context and a *partial* task_struct (only the fields we read).
// CO-RE relocates the partial struct's field offsets against the running
// kernel's BTF at load time, thanks to preserve_access_index + BPF_CORE_READ.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16

// Event streamed to userspace. Keep this layout in sync with the Go side;
// bpf2go regenerates the matching Go struct from this type's BTF.
struct event {
	__u32 pid;
	__u32 ppid;
	__u64 cgroup_id;
	__u8 comm[16];
	__u8 parent_comm[TASK_COMM_LEN];
	__u8 filename[256];
};

// Force bpf2go's BTF type generation to emit `struct event`. Unused otherwise.
struct event *unused_event __attribute__((unused));

// Partial task_struct: only the fields we touch. CO-RE resolves their real
// offsets against the kernel BTF at load time.
struct task_struct {
	struct task_struct *real_parent;
	__u32 tgid;
	char comm[TASK_COMM_LEN];
} __attribute__((preserve_access_index));

// Tracepoint context for sched/sched_process_exec. Field offsets match the
// kernel's tracepoint format: the common header (8 bytes) followed by a
// __data_loc filename, then pid/old_pid.
struct trace_event_sched_process_exec {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	__u32 data_loc_filename; // __data_loc char[]: low 16 bits = byte offset
	__s32 pid;
	__s32 old_pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MiB
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

SEC("tracepoint/sched/sched_process_exec")
int on_process_exec(struct trace_event_sched_process_exec *ctx)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 key = 0;
		__u64 *count = bpf_map_lookup_elem(&dropped_events, &key);
		if (count)
			(*count)++;
		return 0;
	}

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32; // tgid (userspace PID)

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	BPF_CORE_READ_STR_INTO(&e->parent_comm, task, real_parent, comm);

	e->cgroup_id = bpf_get_current_cgroup_id();

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// __data_loc: low 16 bits of the field are the byte offset, from the
	// start of the tracepoint ctx, to the variable-length filename string.
	__u32 off = ctx->data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
