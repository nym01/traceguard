#!/usr/bin/env bash
#
# perf_steadystate.sh — measure traceguard's CPU overhead in steady-state
# (alerts-only) mode under a burst of exec() load. This is the contrast to
# perf_test.sh, which measures the heavier -verbose mode (every event
# marshaled and written to the log).
#
# traceguard must already be running, started (in another terminal, as
# root) WITHOUT -verbose, e.g.:
#
#   sudo ./traceguard -log-file perf_steadystate.log
#
# Then, with no root needed:
#
#   ./perf_steadystate.sh
#
# It runs /bin/true 2000 times as fast as possible (real exec() syscall
# load for the exec monitor) and reports traceguard's CPU% over the
# window. The "events captured" sanity check from perf_test.sh is omitted
# on purpose: in alerts-only mode the /bin/true burst fires no rule, so
# the log stays empty and there is nothing to count.

set -euo pipefail

# bc is required for the floating-point math.
if ! which bc >/dev/null 2>&1; then
    echo "bc not found; installing (needs sudo)..." >&2
    sudo apt-get install -y bc
fi

# traceguard must already be running.
PID="$(pgrep -f './traceguard' | head -n1 || true)"
if [ -z "$PID" ]; then
    echo "error: traceguard does not appear to be running." >&2
    echo "       start it first (in another terminal, as root, non-verbose):" >&2
    echo "       sudo ./traceguard -log-file perf_steadystate.log" >&2
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

# --- Baseline ---
CPU_BEFORE="$(cpu_ticks "$PID")"
T_BEFORE="$(date +%s.%N)"

# --- Generate load: 2000 real exec()s as fast as possible ---
N=2000
for i in $(seq 1 "$N"); do /bin/true; done

# Let any remaining ring-buffer events flush through the pipeline.
sleep 1

# --- After ---
CPU_AFTER="$(cpu_ticks "$PID")"
T_AFTER="$(date +%s.%N)"

# --- Compute ---
ELAPSED="$(echo "$T_AFTER - $T_BEFORE" | bc -l)"
EXEC_RATE="$(echo "$N / $ELAPSED" | bc -l)"
CPU_SECS="$(echo "($CPU_AFTER - $CPU_BEFORE) / $CLK_TCK" | bc -l)"
CPU_PCT="$(echo "$CPU_SECS / $ELAPSED * 100" | bc -l)"

# --- Report ---
echo
echo "TraceGuard Performance Overhead — steady-state (alerts-only mode)"
echo "================================================================"
echo "traceguard PID:        $PID"
echo "Measurement window:    $(printf '%.3f' "$ELAPSED") s"
echo
printf "exec() calls generated:  %d  (%.0f/s)\n" "$N" "$EXEC_RATE"
printf "traceguard CPU usage:    %.2f%%\n" "$CPU_PCT"
