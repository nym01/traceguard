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
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
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
	webhook := flag.String("webhook", "", "if set, POST each alert as JSON to this URL (default: disabled)")
	logFile := flag.String("log-file", "", "if set, also append all output to this file (default: stdout only)")
	flag.Parse()

	// Load and parse the rule config once, before any monitor starts. If this
	// fails there is nothing to evaluate against, so fail fast with a clear
	// error rather than booting the eBPF programs.
	ruleConfig, err := loadRules(*rulesPath)
	if err != nil {
		return err
	}

	// Optional webhook sender. When -webhook is unset, webhookCh stays nil and
	// sendAlert below becomes a no-op, so the rest of the pipeline is unaware
	// of whether a webhook is configured. The buffer absorbs short bursts; the
	// sender drops (and logs) rather than block detection on network I/O.
	var webhookCh chan Alert
	var webhookWG sync.WaitGroup
	if *webhook != "" {
		// Validate the URL once at startup so a typo (or an unparseable
		// value) fails loudly here rather than in a per-alert error loop
		// forever after. Only http/https make sense for an HTTP POST.
		u, err := url.Parse(*webhook)
		if err != nil {
			return fmt.Errorf("parse webhook URL %q: %w", *webhook, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("webhook URL %q must use the http or https scheme (got %q)", *webhook, u.Scheme)
		}
		if u.Scheme == "http" {
			fmt.Fprintln(os.Stderr, "traceguard: warning: webhook URL uses http, not https — alert contents (file paths, process names, IPs) will be sent unencrypted")
		}
		webhookCh = make(chan Alert, 100)
		startWebhookSender(*webhook, webhookCh, &webhookWG)
	}

	// Output writer: stdout by default, mirrored to a log file when -log-file
	// is set. Opening the file is fatal so a bad path surfaces at startup
	// rather than silently dropping the log. The file is closed on return.
	var w io.Writer = os.Stdout
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("open log file %q: %w", *logFile, err)
		}
		defer f.Close()
		w = io.MultiWriter(os.Stdout, f)
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
	// ringbuf.ErrClosed and its reader goroutine exits. The same signal also
	// closes reporterStop so the drop-counter reporter goroutine exits cleanly.
	reporterStop := make(chan struct{})
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		execRD.Close()
		fileRD.Close()
		netRD.Close()
		close(reporterStop)
	}()

	// Dropped-event counters: each monitor's BPF program bumps a per-CPU
	// counter whenever bpf_ringbuf_reserve() fails (ring buffer full). We poll
	// these to surface that otherwise-silent failure mode. PossibleCPU sizes
	// the per-CPU lookup slice used by readDropped below.
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("query possible CPU count: %w", err)
	}
	dropMonitors := []dropMonitor{
		{name: "exec", m: execObjs.DroppedEvents},
		{name: "file", m: fileObjs.DroppedEvents},
		{name: "network", m: netObjs.DroppedEvents},
	}

	// One reader goroutine per monitor; the WaitGroup lets us close the shared
	// channel only once all three (exec/file/network) have drained, so the
	// printer flushes every buffered event before main() returns.
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

	// Drop-counter reporter: every 30s, read each monitor's per-CPU dropped
	// counter and, if it climbed since the last check, warn on stderr. It
	// shares the same shutdown WaitGroup and stops on reporterStop (the same
	// signal that closes the ring-buffer readers).
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		prev := make([]uint64, len(dropMonitors))
		for {
			select {
			case <-reporterStop:
				return
			case <-ticker.C:
				for i, mon := range dropMonitors {
					total, err := readDropped(mon.m, numCPU)
					if err != nil {
						fmt.Fprintf(os.Stderr, "traceguard: read %s dropped counter: %v\n", mon.name, err)
						continue
					}
					if total > prev[i] {
						fmt.Fprintf(os.Stderr, "traceguard: warning: dropped %d %s events in the last 30s (ring buffer full)\n", total-prev[i], mon.name)
					}
					prev[i] = total
				}
			}
		}
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
					fmt.Fprintln(w, string(b))
				} else {
					fmt.Fprintf(os.Stderr, "traceguard: marshal verbose event: %v\n", err)
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
					CgroupID:  a.CgroupID,
					Container: a.Container,
					Comm:      a.Comm,
					Filename:  a.Filename,
					Dst:       a.Dst,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "traceguard: encode alert: %v\n", err)
					continue
				}
				fmt.Fprintln(w, string(b))
				// Mirror the alert to the webhook sender. No-op when no webhook
				// is configured (webhookCh is nil); never blocks the consumer.
				sendAlert(webhookCh, *a)
			}
		}
	}()

	fmt.Fprintln(os.Stderr, "traceguard: monitoring process execs, file access, and network connections (Ctrl-C to stop)")

	wg.Wait()  // all three readers (exec/file/network) plus the reporter have exited
	close(out) // no more events; let the printer drain and stop
	<-done     // printer flushed everything

	// Final drop summary for the whole run, printed unconditionally. A line of
	// zeros on a clean run is a positive "nothing was dropped" confirmation,
	// not just silence. The maps are still open here — execObjs/fileObjs/
	// netObjs are only Closed by the deferred calls when run() returns.
	for _, mon := range dropMonitors {
		total, err := readDropped(mon.m, numCPU)
		if err != nil {
			fmt.Fprintf(os.Stderr, "traceguard: read %s dropped counter: %v\n", mon.name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "traceguard: dropped %d %s events total this run (ring buffer full)\n", total, mon.name)
	}

	// Alerts still queued in the webhook channel are flushed before exit
	// rather than dropped: the printer (sole sender on webhookCh) is now
	// done, so closing the channel lets the sender's range loop end after
	// draining, and we wait for it to finish.
	if webhookCh != nil {
		close(webhookCh)
		webhookWG.Wait()
	}
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
	CgroupID  uint64 `json:"cgroup_id,omitempty"`
	Container string `json:"container,omitempty"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename,omitempty"`
	Dst       string `json:"dst,omitempty"`
}

// dropMonitor pairs a human-readable monitor name with its dropped_events map,
// so the reporter and shutdown summary can iterate the three monitors uniformly.
type dropMonitor struct {
	name string
	m    *ebpf.Map
}

// readDropped sums a monitor's per-CPU dropped-event counters into a single
// total. dropped_events is a single-entry PERCPU_ARRAY, so cilium/ebpf wants
// the lookup destination to be a slice with one slot per possible CPU; each
// CPU bumped its own slot lock-free in-kernel, and we add them up here.
func readDropped(m *ebpf.Map, numCPU int) (uint64, error) {
	var key uint32
	perCPU := make([]uint64, numCPU)
	if err := m.Lookup(&key, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
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
			// Back off before retrying: if the error is persistent (not a
			// one-off), an immediate continue would tight-loop and pin a
			// core while flooding stderr. A short sleep degrades gracefully.
			time.Sleep(100 * time.Millisecond)
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
		CgroupID:   raw.CgroupId,
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
		CgroupID: raw.CgroupId,
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
		Type:     "network",
		PID:      raw.Pid,
		CgroupID: raw.CgroupId,
		Comm:     goString(raw.Comm[:]),
		DstIP:    net.IP(raw.DstIp[:]).String(),
		DstPort:  raw.DstPort,
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
