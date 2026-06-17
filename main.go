// Sentinel — Step 1: process-execution monitor.
//
// Loads an eBPF program onto the sched_process_exec tracepoint, which fires
// once per *successful* execve/execveat, and streams each event to stdout as
// one JSON object per line.
//
// This is the foundation pipeline. Later steps (file access, network) reuse
// the same ring-buffer-to-Go-JSON shape, so the event loop is kept generic.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" -type event execmon bpf/execmon.bpf.c

// execEvent is the user-facing JSON shape for one process-exec event. It is
// decoded from the raw ring-buffer sample (via the bpf2go-generated
// execmonEvent) and enriched with a wall-clock timestamp.
type execEvent struct {
	Timestamp string `json:"timestamp"`
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	CgroupID  uint64 `json:"cgroup_id"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sentinel: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// eBPF maps and programs are charged against a per-process memory-lock
	// limit on older kernels; lift it so the load doesn't fail with EPERM.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs execmonObjects
	if err := loadExecmonObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.OnProcessExec, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ring buffer reader: %w", err)
	}
	defer rd.Close()

	// Close the reader on SIGINT/SIGTERM so the blocking Read below returns
	// ringbuf.ErrClosed and the loop exits cleanly instead of hanging.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		rd.Close()
	}()

	fmt.Fprintln(os.Stderr, "sentinel: monitoring process execs (Ctrl-C to stop)")

	enc := json.NewEncoder(os.Stdout)
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil // clean shutdown
			}
			fmt.Fprintf(os.Stderr, "sentinel: read ring buffer: %v\n", err)
			continue
		}

		var raw execmonEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: decode sample: %v\n", err)
			continue
		}

		ev := execEvent{
			Timestamp: time.Now().Format(time.RFC3339Nano),
			PID:       raw.Pid,
			PPID:      raw.Ppid,
			CgroupID:  raw.CgroupId,
			Comm:      goString(raw.Comm[:]),
			Filename:  goString(raw.Filename[:]),
		}
		if err := enc.Encode(&ev); err != nil {
			fmt.Fprintf(os.Stderr, "sentinel: encode event: %v\n", err)
		}
	}
}

// goString converts a fixed-size, NUL-terminated C char buffer into a Go
// string, cutting at the first NUL.
func goString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
