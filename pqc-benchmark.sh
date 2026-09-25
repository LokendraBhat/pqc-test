#!/usr/bin/env bash
###############################################################################
# pqc_benchmark.sh
# Real PQC TLS handshake measurement script
#
# Measures actual handshake latency, throughput, and wire cost against a
# running nginx + OQS provider deployment.
#
# Usage:
#   ./pqc_benchmark.sh [HOSTNAME] [PORT]
# Defaults: localhost:443 (run on the VM itself)
# Example:
#   ./pqc_benchmark.sh localhost 443
#   ./pqc_benchmark.sh pqc.example.com 443
#
# This script must be run on a machine where the OQS provider is installed.
# Loopback measurement (running on the VM) isolates cryptographic processing
# cost from network variability and is the recommended setup for this study.
#
# Output: results.csv
###############################################################################

set -uo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
HOST="${1:-localhost}"
PORT="${2:-443}"
SAMPLES_PER_ALGO=100   # adjust if you want more/fewer samples per algorithm
TIME_RUN_SECONDS=10    # for throughput test (s_time duration)
OUT_CSV="results.csv"
OQS_PROVIDER_PATH=""   # leave empty if oqs-provider loads from default config

# Algorithms to test (curve names as known to OpenSSL with OQS provider)
ALGORITHMS=(
  "X25519:classical"
  "P-256:classical"
  "X25519MLKEM768:hybrid"
  "SecP256r1MLKEM768:hybrid"
)

# ──────────────────────────────────────────────────────────────────────────────
# SANITY CHECKS
# ──────────────────────────────────────────────────────────────────────────────
if [[ -z "$HOST" ]]; then
  echo "Usage: $0 [HOSTNAME] [PORT]"
  echo "Defaults: pqc.example.com:443"
  exit 1
fi

for tool in openssl curl awk bc; do
  if ! command -v "$tool" &>/dev/null; then
    echo "ERROR: $tool not installed"
    exit 1
  fi
done

# Verify hostname resolves (skip check for localhost / 127.0.0.1)
if [[ "$HOST" != "localhost" && "$HOST" != "127.0.0.1" ]]; then
  echo "Checking hostname resolution for $HOST ..."
  if ! getent hosts "$HOST" &>/dev/null && ! host "$HOST" &>/dev/null 2>&1; then
    echo "WARNING: $HOST does not resolve."
    echo "  Make sure your /etc/hosts has an entry for it, or use 'localhost'."
    echo
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
  fi
fi

echo "Target:      $HOST:$PORT"
echo "Samples:     $SAMPLES_PER_ALGO per algorithm"
echo "Algorithms:  ${#ALGORITHMS[@]}"
echo "Output:      $OUT_CSV"
echo

# ──────────────────────────────────────────────────────────────────────────────
# TEST CONNECTIVITY FIRST
# ──────────────────────────────────────────────────────────────────────────────
echo "Checking connectivity to $HOST:$PORT ..."
if ! timeout 3 bash -c "</dev/tcp/$HOST/$PORT" 2>/dev/null; then
  echo "ERROR: Cannot connect to $HOST:$PORT"
  exit 1
fi
echo "OK"
echo

# ──────────────────────────────────────────────────────────────────────────────
# CSV HEADER
# ──────────────────────────────────────────────────────────────────────────────
echo "algorithm,type,samples,mean_ms,median_ms,p95_ms,min_ms,max_ms,stddev_ms,throughput_conn_per_10s,handshake_bytes" > "$OUT_CSV"

# ──────────────────────────────────────────────────────────────────────────────
# MEASURE FUNCTION
# ──────────────────────────────────────────────────────────────────────────────
measure_algorithm() {
  local algo="$1"
  local type="$2"
  local tmpfile
  tmpfile=$(mktemp)

  echo "── Measuring $algo [$type] ──────────────────────────────────────────"

  # Verify the algorithm actually negotiates before benchmarking.
  # We use the exit code of openssl s_client: 0 = handshake succeeded,
  # non-zero = handshake failed (e.g. server alert).
  # Output contains a self-signed cert verification warning which we ignore.
  echo -n "  Verifying handshake ... "
  local verify_output
  verify_output=$(timeout 5 bash -c "echo Q | openssl s_client \
      -connect '$HOST:$PORT' \
      -groups '$algo' \
      -tls1_3 \
      -no_ign_eof \
      -provider oqsprovider -provider default \
      </dev/null 2>&1")
  # Look for actual TLS alert (handshake failure) — these indicate real rejection
  if echo "$verify_output" | grep -qi "alert handshake failure\|alert number 40\|no shared cipher"; then
    echo "REJECTED BY SERVER (skipping)"
    rm -f "$tmpfile"
    return
  fi
  # Look for evidence of successful handshake — DONE marker or Peer Temp Key line
  if ! echo "$verify_output" | grep -qE "Peer Temp Key|Negotiated TLS|^DONE"; then
    echo "FAILED (no handshake evidence; skipping)"
    rm -f "$tmpfile"
    return
  fi
  echo "OK"

  # Latency samples — using openssl s_client with -no_ign_eof for clean exit
  echo -n "  Collecting $SAMPLES_PER_ALGO latency samples "
  for i in $(seq 1 "$SAMPLES_PER_ALGO"); do
    local t_start t_end ms
    t_start=$(date +%s%N)
    timeout 5 bash -c "echo Q | openssl s_client \
        -connect '$HOST:$PORT' \
        -groups '$algo' \
        -tls1_3 \
        -no_ign_eof \
        -provider oqsprovider -provider default \
        </dev/null >/dev/null 2>&1"
    t_end=$(date +%s%N)
    ms=$(( (t_end - t_start) / 1000000 ))
    echo "$ms" >> "$tmpfile"
    if (( i % 10 == 0 )); then echo -n "."; fi
  done
  echo " done"

  # Statistics
  local stats
  stats=$(awk '
    {
      vals[NR] = $1
      sum += $1
      if ($1 < min || NR == 1) min = $1
      if ($1 > max) max = $1
    }
    END {
      n = NR
      mean = sum / n
      # Sort for median and p95
      asort(vals)
      median = (n % 2 == 1) ? vals[(n+1)/2] : (vals[n/2] + vals[n/2+1]) / 2
      p95_idx = int(n * 0.95)
      if (p95_idx < 1) p95_idx = 1
      p95 = vals[p95_idx]
      # Standard deviation
      sumsq = 0
      for (i = 1; i <= n; i++) sumsq += (vals[i] - mean)^2
      stddev = sqrt(sumsq / n)
      printf "%.1f,%.1f,%.1f,%d,%d,%.1f", mean, median, p95, min, max, stddev
    }
  ' "$tmpfile")

  echo "  Latency stats: $stats"

  # Throughput: count completed handshakes in a fixed time window.
  # We use s_client because s_time does not support the -groups flag
  # on this OpenSSL build. Run for $TIME_RUN_SECONDS seconds and count
  # successful handshakes.
  echo -n "  Measuring throughput ($TIME_RUN_SECONDS s) ... "
  local conn_count=0
  local tp_start tp_end tp_now
  tp_start=$(date +%s)
  tp_end=$((tp_start + TIME_RUN_SECONDS))

  while :; do
    tp_now=$(date +%s)
    if (( tp_now >= tp_end )); then break; fi

    if timeout 3 bash -c "echo Q | openssl s_client \
        -connect '$HOST:$PORT' \
        -groups '$algo' \
        -tls1_3 \
        -no_ign_eof \
        -provider oqsprovider -provider default \
        </dev/null >/dev/null 2>&1"; then
      conn_count=$((conn_count + 1))
    fi
  done

  # Normalise to "connections per 10 seconds"
  local throughput_per_10s
  throughput_per_10s=$(awk -v c="$conn_count" -v t="$TIME_RUN_SECONDS" \
    'BEGIN { printf "%.0f", (c / t) * 10 }')
  echo "$conn_count handshakes in ${TIME_RUN_SECONDS}s → $throughput_per_10s conn/10s"

  # Measure handshake bytes by parsing s_client -msg output.
  # -msg prints "<<<" (received) and ">>>" (sent) lines with byte counts.
  # We sum the byte counts from all handshake messages.
  echo -n "  Measuring handshake bytes ... "
  local hs_bytes
  hs_bytes=$(timeout 5 bash -c "echo Q | openssl s_client \
      -connect '$HOST:$PORT' \
      -groups '$algo' \
      -tls1_3 \
      -no_ign_eof \
      -msg \
      -provider oqsprovider -provider default \
      </dev/null 2>&1" \
    | grep -oE '(read|written) [0-9]+ bytes' \
    | awk '{sum += $2} END {print sum+0}')

  if [[ -z "$hs_bytes" || "$hs_bytes" == "0" ]]; then
    # Fallback: grab the "SSL handshake has read X bytes and written Y bytes" summary line
    hs_bytes=$(timeout 5 bash -c "echo Q | openssl s_client \
        -connect '$HOST:$PORT' \
        -groups '$algo' \
        -tls1_3 \
        -no_ign_eof \
        -provider oqsprovider -provider default \
        </dev/null 2>&1" \
      | grep -oE 'SSL handshake has read [0-9]+ bytes and written [0-9]+ bytes' \
      | awk '{print $5 + $9}')
  fi

  hs_bytes=${hs_bytes:-0}
  echo "$hs_bytes bytes"

  # Write CSV row
  echo "$algo,$type,$SAMPLES_PER_ALGO,$stats,$throughput_per_10s,$hs_bytes" >> "$OUT_CSV"

  rm -f "$tmpfile"
  echo
}

# ──────────────────────────────────────────────────────────────────────────────
# RUN ALL ALGORITHMS
# ──────────────────────────────────────────────────────────────────────────────
for entry in "${ALGORITHMS[@]}"; do
  IFS=':' read -r algo type <<< "$entry"
  measure_algorithm "$algo" "$type"
done

# ──────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════════════════════════════════"
echo " BENCHMARK COMPLETE"
echo "══════════════════════════════════════════════════════════════════════"
echo
echo "Results written to: $OUT_CSV"
echo
column -t -s, "$OUT_CSV" | head -20
echo
echo "Done."
