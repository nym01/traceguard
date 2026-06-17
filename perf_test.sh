#!/usr/bin/env bash
#
# perf_test.sh — measure traceguard's CPU overhead under a burst of exec()
# load. traceguard must already be running, started (in another terminal,
# as root) with:
#
#   sudo ./traceguard -verbose -log-file perf.log
#
# Then, with no root needed:
#
#   ./perf_test.sh perf.log
#
# It runs /bin/true 2000 times as fast as possible (real exec() syscall
# load for the exec monitor), and reports the exec rate, how many of those
# execs traceguard actually captured in the log, and traceguard's CPU%
# over the measurement window.

set -euo pipefail

LOG="${1:-perf.log}"

# bc is required for the floating-point math.
if ! which bc >/dev/null 2>&1; then
    echo "bc not found; installing (needs sudo)..." >&2
    sudo apt-get install -y bc
fi

# traceguard must already be running.
PID="$(pgrep -f './traceguard' | head -n1 || true)"
if [ -z "$PID" ]; then
    echo "error: traceguard does not appear to be running." >&2
    echo "       start it first (in another terminal, as root):" >&2
    echo "       sudo ./traceguard -verbose -log-file $LOG" >&2
    exit 1
fi

if [ ! -f "$LOG" ]; then
    echo "error: log file '$LOG' not found." >&2
    echo "       it must match the path traceguard was started with via -log-file." >&2
    exit 1
fi

CLK_TCK="$(getconf CLK_TCK)"

# cpu_ticks <pid> — sum of utime (field 14) + stime (field 15) from
# /proc/<pid>/stat. The comm field (field 2) is parenthesized and may
# contain spaces, which would shift naive field numbering; strip
# everything up to and including the last ") " first, after which the
# remaining fields start at field 3 (so utime is the 12th remaining
# field, stime the 13th).
cpu_ticks() {
    local stat rest
    stat="$(cat "/proc/$1/stat")"
    rest="${stat##*) }"
    echo "$rest" | awk '{print $12 + $13}'
}

# Count of captured exec events for /bin/true so far. The -verbose raw
# event stream serializes Event with lowercase JSON keys, consistent with
# the alert lines. We match exec-type lines specifically: each /bin/true
# also produces a file_access event (its dynamic linker opening
# /etc/ld.so.cache) carrying the same comm "true", which would otherwise
# double the count. /bin/true never fires a rule, so these verbose events
# are the only lines this can match.
true_count() {
    grep -c '"type":"exec".*"comm":"true"' "$LOG" || true
}

# --- Baseline ---
CPU_BEFORE="$(cpu_ticks "$PID")"
TRUE_BEFORE="$(true_count)"
T_BEFORE="$(date +%s.%N)"

# --- Generate load: 2000 real exec()s as fast as possible ---
N=2000
for i in $(seq 1 "$N"); do /bin/true; done

# Let any remaining ring-buffer events flush through the pipeline.
sleep 1

# --- After ---
CPU_AFTER="$(cpu_ticks "$PID")"
TRUE_AFTER="$(true_count)"
T_AFTER="$(date +%s.%N)"

# --- Compute ---
ELAPSED="$(echo "$T_AFTER - $T_BEFORE" | bc -l)"
EXEC_RATE="$(echo "$N / $ELAPSED" | bc -l)"

CAPTURED="$((TRUE_AFTER - TRUE_BEFORE))"
CAPTURE_RATE="$(echo "$CAPTURED / $ELAPSED" | bc -l)"

CPU_SECS="$(echo "($CPU_AFTER - $CPU_BEFORE) / $CLK_TCK" | bc -l)"
CPU_PCT="$(echo "$CPU_SECS / $ELAPSED * 100" | bc -l)"

# --- Report ---
echo
echo "TraceGuard Performance Overhead"
echo "==============================="
echo "traceguard PID:        $PID"
echo "Measurement window:    $(printf '%.3f' "$ELAPSED") s"
echo
printf "exec() calls generated:  %d  (%.0f/s)\n" "$N" "$EXEC_RATE"
printf "exec() events captured:  %d  (%.0f/s)\n" "$CAPTURED" "$CAPTURE_RATE"
printf "traceguard CPU usage:    %.2f%%\n" "$CPU_PCT"
