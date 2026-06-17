// TraceGuard — Steps 1 & 2: process-execution and file-access monitors.
//
// Step 1 loads an eBPF program onto the sched_process_exec tracepoint (fires
// once per successful execve/execveat). Step 2 adds a second program on the
// sys_enter_openat tracepoint (fires on every openat(), the syscall modern
// open() funnels through). Each monitor streams its events over its own ring
// buffer; we fan them into one shared channel and print one JSON object per
// line.
//
// The structure is deliberately generic: a later network monitor drops in as a
// third reader goroutine on the same channel with no further refactoring.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" -type event execmon bpf/execmon.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" -type event filemon bpf/filemon.bpf.c

// execEvent is the user-facing JSON shape for one process-exec event. It is
// decoded from the raw ring-buffer sample (via the bpf2go-generated
// execmonEvent) and enriched with a wall-clock timestamp.
type execEvent struct {
	Type      string `json:"type"` // always "exec"
	Timestamp string `json:"timestamp"`
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	CgroupID  uint64 `json:"cgroup_id"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename"`
}

// fileEvent is the user-facing JSON shape for one file-access event, decoded
// from the bpf2go-generated filemonEvent.
type fileEvent struct {
	Type      string `json:"type"` // always "file_access"
	Timestamp string `json:"timestamp"`
	PID       uint32 `json:"pid"`
	Flags     uint32 `json:"flags"`
	CgroupID  uint64 `json:"cgroup_id"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "traceguard: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// eBPF maps and programs are charged against a per-process memory-lock
	// limit on older kernels; lift it so the load doesn't fail with EPERM.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	// --- Step 1: process-exec monitor ---
	var execObjs execmonObjects
	if err := loadExecmonObjects(&execObjs, nil); err != nil {
		return fmt.Errorf("load execmon objects: %w", err)
	}
	defer execObjs.Close()

	execTP, err := link.Tracepoint("sched", "sched_process_exec", execObjs.OnProcessExec, nil)
	if err != nil {
		return fmt.Errorf("attach exec tracepoint: %w", err)
	}
	defer execTP.Close()

	execRD, err := ringbuf.NewReader(execObjs.Events)
	if err != nil {
		return fmt.Errorf("open exec ring buffer reader: %w", err)
	}
	defer execRD.Close()

	// --- Step 2: file-access monitor ---
	var fileObjs filemonObjects
	if err := loadFilemonObjects(&fileObjs, nil); err != nil {
		return fmt.Errorf("load filemon objects: %w", err)
	}
	defer fileObjs.Close()

	fileTP, err := link.Tracepoint("syscalls", "sys_enter_openat", fileObjs.OnOpenat, nil)
	if err != nil {
		return fmt.Errorf("attach openat tracepoint: %w", err)
	}
	defer fileTP.Close()

	fileRD, err := ringbuf.NewReader(fileObjs.Events)
	if err != nil {
		return fmt.Errorf("open file ring buffer reader: %w", err)
	}
	defer fileRD.Close()

	// Shared output channel: every reader marshals its event to JSON and sends
	// the bytes here. A single printer goroutine writes them out, so two
	// concurrent readers can't interleave a half-written line on stdout.
	out := make(chan []byte, 64)

	// Close both readers on SIGINT/SIGTERM so each blocking Read returns
	// ringbuf.ErrClosed and its reader goroutine exits.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		execRD.Close()
		fileRD.Close()
	}()

	// One reader goroutine per monitor; the WaitGroup lets us close the shared
	// channel only once both have drained, so the printer flushes every
	// buffered event before main() returns.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		readLoop(execRD, out, decodeExec)
	}()
	go func() {
		defer wg.Done()
		readLoop(fileRD, out, decodeFile)
	}()

	// Printer: the sole writer to stdout.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for b := range out {
			fmt.Println(string(b))
		}
	}()

	fmt.Fprintln(os.Stderr, "traceguard: monitoring process execs and file access (Ctrl-C to stop)")

	wg.Wait()    // both readers have exited
	close(out)   // no more events; let the printer drain and stop
	<-done       // printer flushed everything
	return nil
}

// readLoop pulls raw samples off one ring buffer, hands each to a monitor's
// decoder, and forwards the resulting JSON bytes to the shared channel. It
// returns when the reader is closed (ringbuf.ErrClosed) on shutdown.
func readLoop(rd *ringbuf.Reader, out chan<- []byte, decode func([]byte) ([]byte, error)) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return // clean shutdown
			}
			fmt.Fprintf(os.Stderr, "traceguard: read ring buffer: %v\n", err)
			continue
		}
		b, err := decode(record.RawSample)
		if err != nil {
			fmt.Fprintf(os.Stderr, "traceguard: %v\n", err)
			continue
		}
		out <- b
	}
}

// decodeExec turns a raw execmon ring-buffer sample into a marshaled execEvent.
func decodeExec(sample []byte) ([]byte, error) {
	var raw execmonEvent
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("decode exec sample: %w", err)
	}
	ev := execEvent{
		Type:      "exec",
		Timestamp: time.Now().Format(time.RFC3339Nano),
		PID:       raw.Pid,
		PPID:      raw.Ppid,
		CgroupID:  raw.CgroupId,
		Comm:      goString(raw.Comm[:]),
		Filename:  goString(raw.Filename[:]),
	}
	b, err := json.Marshal(&ev)
	if err != nil {
		return nil, fmt.Errorf("encode exec event: %w", err)
	}
	return b, nil
}

// decodeFile turns a raw filemon ring-buffer sample into a marshaled fileEvent.
func decodeFile(sample []byte) ([]byte, error) {
	var raw filemonEvent
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("decode file sample: %w", err)
	}
	ev := fileEvent{
		Type:      "file_access",
		Timestamp: time.Now().Format(time.RFC3339Nano),
		PID:       raw.Pid,
		Flags:     raw.Flags,
		CgroupID:  raw.CgroupId,
		Comm:      goString(raw.Comm[:]),
		Filename:  goString(raw.Filename[:]),
	}
	b, err := json.Marshal(&ev)
	if err != nil {
		return nil, fmt.Errorf("encode file event: %w", err)
	}
	return b, nil
}

// goString converts a fixed-size, NUL-terminated C char buffer into a Go
// string, cutting at the first NUL.
func goString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
