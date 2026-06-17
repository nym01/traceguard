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
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" -type event execmon bpf/execmon.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" -type event filemon bpf/filemon.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" -type event netmon bpf/netmon.bpf.c

// loadRules reads and parses a YAML rule-config file into a RuleConfig. A
// failure here is fatal at startup: with no rules there is nothing to alert
// on, so the caller exits rather than run blind.
func loadRules(path string) (RuleConfig, error) {
	var cfg RuleConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read rules file %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse rules file %q: %w", path, err)
	}
	return cfg, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "traceguard: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	rulesPath := flag.String("rules", "rules.yaml", "path to the YAML rule-config file")
	verbose := flag.Bool("verbose", false, "also print the raw telemetry stream (default: alerts only)")
	flag.Parse()

	// Load and parse the rule config once, before any monitor starts. If this
	// fails there is nothing to evaluate against, so fail fast with a clear
	// error rather than booting the eBPF programs.
	ruleConfig, err := loadRules(*rulesPath)
	if err != nil {
		return err
	}

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

	// --- Step 3: network-connection monitor ---
	var netObjs netmonObjects
	if err := loadNetmonObjects(&netObjs, nil); err != nil {
		return fmt.Errorf("load netmon objects: %w", err)
	}
	defer netObjs.Close()

	netTP, err := link.Tracepoint("syscalls", "sys_enter_connect", netObjs.OnConnect, nil)
	if err != nil {
		return fmt.Errorf("attach connect tracepoint: %w", err)
	}
	defer netTP.Close()

	netRD, err := ringbuf.NewReader(netObjs.Events)
	if err != nil {
		return fmt.Errorf("open net ring buffer reader: %w", err)
	}
	defer netRD.Close()

	// Shared event channel: every reader decodes its raw sample into the unified
	// Event and sends it here. A single consumer goroutine evaluates rules and
	// writes output, so two concurrent readers can't interleave a half-written
	// line on stdout.
	out := make(chan Event, 64)

	// Close both readers on SIGINT/SIGTERM so each blocking Read returns
	// ringbuf.ErrClosed and its reader goroutine exits.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		execRD.Close()
		fileRD.Close()
		netRD.Close()
	}()

	// One reader goroutine per monitor; the WaitGroup lets us close the shared
	// channel only once both have drained, so the printer flushes every
	// buffered event before main() returns.
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		readLoop(execRD, out, decodeExec)
	}()
	go func() {
		defer wg.Done()
		readLoop(fileRD, out, decodeFile)
	}()
	go func() {
		defer wg.Done()
		readLoop(netRD, out, decodeNet)
	}()

	// Consumer: the sole writer to stdout. With -verbose it dumps the raw event
	// stream; in all modes it runs every event through the rule engine and
	// prints one JSON object per alert that fires.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range out {
			if *verbose {
				if b, err := json.Marshal(&ev); err == nil {
					fmt.Println(string(b))
				}
			}
			for _, a := range Evaluate(ev, ruleConfig) {
				b, err := json.Marshal(alertJSON{
					Type:      "alert",
					Timestamp: time.Now().Format(time.RFC3339Nano),
					Rule:      a.Rule,
					Severity:  string(a.Severity),
					Message:   a.Message,
					PID:       a.PID,
					Comm:      a.Comm,
					Filename:  a.Filename,
					Dst:       a.Dst,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "traceguard: encode alert: %v\n", err)
					continue
				}
				fmt.Println(string(b))
			}
		}
	}()

	fmt.Fprintln(os.Stderr, "traceguard: monitoring process execs, file access, and network connections (Ctrl-C to stop)")

	wg.Wait()  // both readers have exited
	close(out) // no more events; let the printer drain and stop
	<-done     // printer flushed everything
	return nil
}

// alertJSON is the user-facing JSON shape for one fired alert. It mirrors the
// Alert produced by the rule engine, plus a "type":"alert" discriminator and a
// wall-clock timestamp. Empty Filename/Dst fields are omitted so an exec alert
// doesn't carry a blank "dst" and vice versa.
type alertJSON struct {
	Type      string `json:"type"` // always "alert"
	Timestamp string `json:"timestamp"`
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename,omitempty"`
	Dst       string `json:"dst,omitempty"`
}

// readLoop pulls raw samples off one ring buffer, hands each to a monitor's
// decoder, and forwards the resulting Event to the shared channel. It returns
// when the reader is closed (ringbuf.ErrClosed) on shutdown.
func readLoop(rd *ringbuf.Reader, out chan<- Event, decode func([]byte) (Event, error)) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return // clean shutdown
			}
			fmt.Fprintf(os.Stderr, "traceguard: read ring buffer: %v\n", err)
			continue
		}
		ev, err := decode(record.RawSample)
		if err != nil {
			fmt.Fprintf(os.Stderr, "traceguard: %v\n", err)
			continue
		}
		out <- ev
	}
}

// decodeExec turns a raw execmon ring-buffer sample into the unified Event.
func decodeExec(sample []byte) (Event, error) {
	var raw execmonEvent
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return Event{}, fmt.Errorf("decode exec sample: %w", err)
	}
	return Event{
		Type:       "exec",
		PID:        raw.Pid,
		PPID:       raw.Ppid,
		Comm:       goString(raw.Comm[:]),
		ParentComm: goString(raw.ParentComm[:]),
		Filename:   goString(raw.Filename[:]),
	}, nil
}

// decodeFile turns a raw filemon ring-buffer sample into the unified Event.
func decodeFile(sample []byte) (Event, error) {
	var raw filemonEvent
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return Event{}, fmt.Errorf("decode file sample: %w", err)
	}
	return Event{
		Type:     "file_access",
		PID:      raw.Pid,
		Flags:    raw.Flags,
		Comm:     goString(raw.Comm[:]),
		Filename: goString(raw.Filename[:]),
	}, nil
}

// decodeNet turns a raw netmon ring-buffer sample into the unified Event.
func decodeNet(sample []byte) (Event, error) {
	var raw netmonEvent
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return Event{}, fmt.Errorf("decode net sample: %w", err)
	}
	return Event{
		Type:    "network",
		PID:     raw.Pid,
		Comm:    goString(raw.Comm[:]),
		DstIP:   net.IP(raw.DstIp[:]).String(),
		DstPort: uint16(raw.DstPort),
	}, nil
}

// goString converts a fixed-size, NUL-terminated C char buffer into a Go
// string, cutting at the first NUL.
func goString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
