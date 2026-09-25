#!/usr/bin/env bash
# collect_samples.sh - raw TLS 1.3 handshake latencies for a
# (key-exchange group) x (authentication) design, one CSV row per handshake.
#
#   Key exchange (KX_GROUPS):  X25519, P-256, X25519MLKEM768 [, SecP256r1MLKEM768]
#   Authentication (TARGETS):  ecdsa -> port 443, mldsa -> port 8443
#
# Methodology points (write these into Chapter 3):
#   * all group x auth cells are run in ONE randomly interleaved sequence
#   * WARMUP handshakes per cell first, flagged phase=warmup and excluded
#   * the client pins the signature algorithm (-sigalgs) and VERIFIES the chain
#     against the test root (-CAfile), as a real client would
#   * a run counts ok=1 only if TLS 1.3, the requested group, and verify code 0
#   * timing wraps the whole openssl s_client process (includes process start-up)
#
# Usage (loopback):
#   HOST=pqc.example.com PROFILE=loopback ./collect_samples.sh
# Usage (WAN, client in namespace cli, server reachable at 10.9.0.1):
#   ip netns exec cli env HOST=10.9.0.1 SNI=pqc.example.com PROFILE=50ms_0.5pct ./collect_samples.sh
set -u
HOST=${HOST:-pqc.example.com}; SNI=${SNI:-pqc.example.com}
N=${N:-100}; WARMUP=${WARMUP:-10}; PROFILE=${PROFILE:-loopback}
OUT=${OUT:-latency_raw.csv}; TIMEOUT=${TIMEOUT:-20}
CA=${CA:-/root/pqc-bench-ca}
read -r -a KX <<< "${KX_GROUPS:-X25519 P-256 X25519MLKEM768}"
# auth:port:client_sigalg:root_ca
read -r -a TG <<< "${TARGETS:-ecdsa:443:ecdsa_secp256r1_sha256:$CA/ecdsa/root.crt mldsa:8443:mldsa65:$CA/mldsa/root.crt}"
PROVIDER_ARGS=${PROVIDER_ARGS--provider default}   # native OpenSSL >= 3.5

command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
HAVE_NSTAT=0; command -v nstat >/dev/null && HAVE_NSTAT=1

parse_group() {  # hybrid: "Negotiated TLS1.3 group: X"; classical: "Peer Temp Key: X25519, ..." / "ECDH, prime256v1, ..."
  printf '%s\n' "$1" | awk '
    /[Nn]egotiated TLS1\.3 group:/ { s=$0; sub(/.*group: */,"",s); split(s,a," "); print a[1]; exit }
    /(Peer|Server) Temp Key:/      { s=$0; sub(/.*Temp Key: */,"",s); split(s,f,/, */);
                                     if (f[1]=="ECDH") print f[2]; else if (f[1]=="DH") print "DH"; else print f[1]; exit }'
}
norm(){ case "$1" in P-256|secp256r1|prime256v1) echo P-256;; *) echo "$1";; esac; }

[ -f "$OUT" ] || echo "run_id,timestamp,profile,phase,auth,group,latency_ms,ok,negotiated,peer_sig,verify_code,bytes_read,bytes_written,client_retrans,providers" > "$OUT"

handshake() {  # $1 group  $2 target-spec  $3 phase  $4 id
  local g=$1 phase=$3 id=$4 auth port sig cafile
  IFS=: read -r auth port sig cafile <<< "$2"
  local extra=(); [ -n "$cafile" ] && extra=(-CAfile "$cafile" -verify_return_error)
  local t0 t1 out rc ms neg psig vc br bw retx="" ok=0
  [ $HAVE_NSTAT -eq 1 ] && nstat -n >/dev/null 2>&1
  t0=$(date +%s%N)
  out=$(echo Q | timeout "$TIMEOUT" openssl s_client -connect "$HOST:$port" -servername "$SNI" \
        -groups "$g" -sigalgs "$sig" -tls1_3 -no_ign_eof "${extra[@]}" $PROVIDER_ARGS 2>&1)
  rc=$?
  t1=$(date +%s%N)
  ms=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f",(b-a)/1e6}')
  neg=$(parse_group "$out")
  psig=$(printf '%s\n' "$out" | sed -n 's/.*Peer signature type: *//p' | head -1 | tr -d ' ,')
  vc=$(printf '%s\n' "$out" | sed -n 's/.*Verify return code: *\([0-9]*\).*/\1/p' | tail -1)
  br=$(printf '%s\n' "$out" | sed -n 's/.*has read \([0-9]*\) bytes and written.*/\1/p' | head -1)
  bw=$(printf '%s\n' "$out" | sed -n 's/.*and written \([0-9]*\) bytes.*/\1/p' | head -1)
  [ $HAVE_NSTAT -eq 1 ] && retx=$(nstat -z TcpRetransSegs 2>/dev/null | awk '/TcpRetransSegs/{print $2}')
  if [ $rc -eq 0 ] && printf '%s\n' "$out" | grep -q "TLSv1.3" && [ -n "$neg" ] \
     && [ "$(norm "$g")" = "$(norm "$neg")" ] && { [ -z "$cafile" ] || [ "${vc:-1}" = 0 ]; }; then ok=1; fi
  echo "$id,$(date -Iseconds),$PROFILE,$phase,$auth,$g,$ms,$ok,${neg:-none},${psig:-},${vc:-},${br:-},${bw:-},${retx:-},${PROVIDER_ARGS// /_}" >> "$OUT"
}

CELLS=(); for t in "${TG[@]}"; do for g in "${KX[@]}"; do CELLS+=("$g|$t"); done; done
id=0
for c in "${CELLS[@]}"; do for ((i=0;i<WARMUP;i++)); do id=$((id+1)); handshake "${c%%|*}" "${c#*|}" warmup "$PROFILE-w$id"; done; done
mapfile -t ORDER < <(for c in "${CELLS[@]}"; do for ((i=0;i<N;i++)); do echo "$c"; done; done | shuf)
total=${#ORDER[@]}; k=0
for c in "${ORDER[@]}"; do
  k=$((k+1)); handshake "${c%%|*}" "${c#*|}" measure "$PROFILE-$k"
  printf '\r[%s] %d/%d' "$PROFILE" "$k" "$total" >&2
done
echo >&2
awk -F, -v p="$PROFILE" '$3==p && $4=="measure"{k=$5" / "$6; n[k]++; if($8==1) ok[k]++}
  END{for(k in n) printf "  %-28s ok %d / %d\n", k, ok[k], n[k]}' "$OUT" | sort >&2
