#!/usr/bin/env bash
# preflight_check.sh - verify the group x authentication benchmark setup before collecting data.
# Read-only: runs test handshakes and inspects settings; changes nothing.
#   HOST=pqc.example.com ./preflight_check.sh
#   WAN=1 SRV_NS= RTT_MS=50 SNI=pqc.example.com ./preflight_check.sh   (client namespace "cli")
set -u
HOST=${HOST:-pqc.example.com}; SNI=${SNI:-pqc.example.com}; CA=${CA:-/root/pqc-bench-ca}
WAN=${WAN:-0}; RTT_MS=${RTT_MS:-50}; SRV_NS=${SRV_NS-}; WAN_IP=${WAN_IP:-10.9.0.1}
read -r -a KX <<< "${KX_GROUPS:-X25519 P-256 X25519MLKEM768}"
OPTIONAL_KX=(SecP256r1MLKEM768 MLKEM768)
read -r -a TG <<< "${TARGETS:-ecdsa:443:ecdsa_secp256r1_sha256:$CA/ecdsa/root.crt mldsa:8443:mldsa65:$CA/mldsa/root.crt}"
PROVIDER_ARGS=${PROVIDER_ARGS--provider default}
P=0; W=0; F=0
pass(){ echo "  [PASS] $*"; P=$((P+1)); }; warn(){ echo "  [WARN] $*"; W=$((W+1)); }
fail(){ echo "  [FAIL] $*"; F=$((F+1)); }; hdr(){ echo; echo "== $* =="; }
srv_exec(){ if [ -n "$SRV_NS" ]; then ip netns exec "$SRV_NS" "$@"; else "$@"; fi; }
parse_group() {
  printf '%s\n' "$1" | awk '
    /[Nn]egotiated TLS1\.3 group:/ { s=$0; sub(/.*group: */,"",s); split(s,a," "); print a[1]; exit }
    /(Peer|Server) Temp Key:/      { s=$0; sub(/.*Temp Key: */,"",s); split(s,f,/, */);
                                     if (f[1]=="ECDH") print f[2]; else if (f[1]=="DH") print "DH"; else print f[1]; exit }'
}
norm(){ case "$1" in P-256|secp256r1|prime256v1) echo P-256;; *) echo "$1";; esac; }
# hs host port group sigalg cafile -> sets OUT RC NEG PSIG VC BR BW
hs(){
  local extra=(); [ -n "$5" ] && extra=(-CAfile "$5" -verify_return_error)
  OUT=$(echo Q | timeout 20 openssl s_client -connect "$1:$2" -servername "$SNI" -groups "$3" \
        -sigalgs "$4" -tls1_3 -no_ign_eof "${extra[@]}" $PROVIDER_ARGS 2>&1); RC=$?
  NEG=$(parse_group "$OUT"); NEG=${NEG:-none}
  PSIG=$(printf '%s\n' "$OUT" | sed -n 's/.*Peer signature type: *//p' | head -1)
  VC=$(printf '%s\n' "$OUT" | sed -n 's/.*Verify return code: *\([0-9]*\).*/\1/p' | tail -1)
  BR=$(printf '%s\n' "$OUT" | sed -n 's/.*has read \([0-9]*\) bytes and written.*/\1/p' | head -1)
  BW=$(printf '%s\n' "$OUT" | sed -n 's/.*and written \([0-9]*\) bytes.*/\1/p' | head -1)
}

hdr "1. Tools"
for c in openssl timeout shuf awk sed grep; do command -v $c >/dev/null && pass "$c" || fail "$c missing"; done
command -v nstat >/dev/null && pass "nstat" || warn "nstat missing - no retransmission counts"
[[ "$(date +%s%N)" =~ ^[0-9]{19}$ ]] && pass "nanosecond timestamps" || fail "date +%s%N unsupported"

hdr "2. Python"
for m in numpy scipy pandas matplotlib; do python3 -c "import $m" 2>/dev/null && pass "$m" || fail "$m missing"; done

hdr "3. OpenSSL native PQC support (client)"
echo "     $(openssl version)   OPENSSL_CONF=${OPENSSL_CONF:-<unset>}   client providers: ${PROVIDER_ARGS:-<none>}"
openssl list -kem-algorithms $PROVIDER_ARGS 2>/dev/null | grep -qi 'ML-KEM-768' && pass "ML-KEM-768 available" || fail "ML-KEM-768 not available"
openssl list -signature-algorithms $PROVIDER_ARGS 2>/dev/null | grep -qi 'ML-DSA-65' && pass "ML-DSA-65 available" || fail "ML-DSA-65 not available"

hdr "4. Test PKI files"
for t in ecdsa mldsa; do
  for f in root.crt fullchain.pem leaf.key; do [ -r "$CA/$t/$f" ] && pass "$t/$f" || fail "$CA/$t/$f missing (run generate_certs.sh)"; done
done

for spec in "${TG[@]}"; do
  IFS=: read -r auth port sig cafile <<< "$spec"
  hdr "5.$auth  port $port, sigalg $sig"
  cert=$(echo Q | timeout 20 openssl s_client -connect "$HOST:$port" -servername "$SNI" -tls1_3 $PROVIDER_ARGS 2>/dev/null \
         | openssl x509 -noout -text 2>/dev/null | sed -n 's/.*Public Key Algorithm: *//p' | head -1)
  echo "     leaf key served: ${cert:-unknown}"
  case "$auth:$cert" in
    ecdsa:*id-ecPublicKey*|mldsa:*ML-DSA-65*|mldsa:*mldsa65*|mldsa:*ML-DSA*) pass "certificate type matches '$auth'";;
    *) fail "port $port serves '${cert:-nothing}' - expected $auth (check nginx server blocks)";;
  esac
  for g in "${KX[@]}"; do
    hs "$HOST" "$port" "$g" "$sig" "$cafile"
    if [ "$RC" -eq 0 ] && [ "$(norm "$g")" = "$(norm "$NEG")" ] && [ "${VC:-1}" = 0 ]; then
      pass "$g: negotiated $NEG, sig '$PSIG', verify ok, $BR read + $BW written = $((BR+BW)) B"
    else
      fail "$g: rc=$RC negotiated=$NEG verify=${VC:-?}"; printf '%s\n' "$OUT" | grep -iE 'error|alert' | head -3 | sed 's/^/         /'
    fi
  done
  for g in "${OPTIONAL_KX[@]}"; do
    hs "$HOST" "$port" "$g" "$sig" "$cafile"
    [ "$NEG" = "$g" ] && echo "     [info] optional group $g works - you may add it to KX_GROUPS" \
                      || echo "     [info] optional group $g does not negotiate (fine; add to ssl_ecdh_curve if wanted)"
  done
  hs "$HOST" "$port" ffdhe2048 "$sig" "$cafile"
  [ "$NEG" = none ] || [ "$RC" -ne 0 ] && pass "negative control: ffdhe2048 refused" || warn "ffdhe2048 accepted - server offers unlisted groups"
  other=$([ "$auth" = ecdsa ] && echo mldsa65 || echo ecdsa_secp256r1_sha256)
  hs "$HOST" "$port" X25519 "$other" ""
  [ "$RC" -ne 0 ] || [ "$NEG" = none ] && pass "negative control: sigalg $other refused on this port (auth is pinned)" \
    || warn "sigalg $other accepted on $auth port - more than one certificate is configured here"
done

hdr "6. Host conditions"
echo "     CPUs $(nproc), load $(cut -d' ' -f1-3 /proc/loadavg), governor $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
awk -v l="$(cut -d' ' -f1 /proc/loadavg)" -v c="$(nproc)" 'BEGIN{exit !(l<0.5*c)}' && pass "load low" || warn "load high - stop other work"
ss -ltn 2>/dev/null | grep -q ':8000 ' && warn "something listens on :8000 (the /logs proxy backend) - stop it during runs" || true

if [ "$WAN" = 1 ]; then
  hdr "7. WAN emulation (target RTT ${RTT_MS} ms)"
  ip netns list 2>/dev/null | grep -qw cli && pass "namespace cli" || fail "namespace cli missing"
  for dev in v-srv v-cli; do
    if [ $dev = v-cli ]; then run(){ ip netns exec cli "$@"; }; else run(){ srv_exec "$@"; }; fi
    mtu=$(run ip link show $dev 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p')
    [ "$mtu" = 1500 ] && pass "$dev MTU 1500" || fail "$dev MTU '${mtu:-?}'"
    st=$(run cat /sys/class/net/$dev/operstate 2>/dev/null)
    [ "$st" = up ] && pass "$dev link is up" || fail "$dev link state '${st:-missing}' - veth pair broken or peer in wrong namespace"
    q=$(run tc qdisc show dev $dev 2>/dev/null); echo "     $dev: ${q:-no qdisc}"
    echo "$q" | grep -q netem && pass "netem on $dev" || fail "no netem on $dev"
  done
  srv_exec ip -o addr show dev v-srv 2>/dev/null | grep -q " $WAN_IP/" && pass "$WAN_IP is on v-srv in the server's namespace" \
    || fail "$WAN_IP is not on v-srv where nginx runs"
  others=$(ip netns list 2>/dev/null | awk '{print $1}' | grep -vx cli | grep -vx "${SRV_NS:-__none__}")
  [ -n "$others" ] && warn "extra namespaces present: $(echo $others) - a stale one may also own $WAN_IP" || true
  st=$(ip netns exec cli ping -c 30 -i 0.2 -q $WAN_IP 2>/dev/null | awk -F'[ /]+' '/rtt|round-trip/{print $7,$8,$9,$10}')
  if [ -n "$st" ]; then
    read -r rmin ravg rmax rmd <<< "$st"; echo "     RTT min/avg/max/mdev $rmin/$ravg/$rmax/$rmd ms"
    awk -v r="$rmin" -v t="$RTT_MS" 'BEGIN{exit !(r>0.95*t && r<1.15*t)}' && pass "min RTT on target" || fail "min RTT off target"
    awk -v a="$ravg" -v m="$rmin" 'BEGIN{exit !(a-m<5)}' && pass "low jitter" || warn "avg exceeds min by >5 ms - report measured RTT"
  else fail "cannot ping $WAN_IP from cli"; fi
  for spec in "${TG[@]}"; do
    IFS=: read -r auth port sig cafile <<< "$spec"
    if ip netns exec cli timeout 5 bash -c "</dev/tcp/$WAN_IP/$port" 2>/dev/null; then
      pass "TCP $WAN_IP:$port reachable from cli"
      o=$(ip netns exec cli bash -c "echo Q | timeout 20 openssl s_client -connect $WAN_IP:$port -servername $SNI \
          -groups X25519MLKEM768 -sigalgs $sig -tls1_3 -CAfile $cafile -verify_return_error $PROVIDER_ARGS 2>&1")
      [ "$(parse_group "$o")" = X25519MLKEM768 ] && pass "$auth: hybrid handshake across emulated link" \
        || { fail "$auth: TLS fails across link"; printf '%s\n' "$o" | tail -4 | sed 's/^/         /'; }
    else
      fail "TCP $WAN_IP:$port NOT reachable from cli - firewall? try: firewall-cmd --zone=trusted --change-interface=v-srv"
    fi
  done
fi

echo; echo "================ SUMMARY: $P pass, $W warn, $F fail ================"
[ $F -eq 0 ] && echo "Next: N=3 WARMUP=1 OUT=dryrun.csv ./collect_samples.sh && python3 analyze_stats.py dryrun.csv --outdir dryrun" \
             || echo "Fix FAIL items first."
exit $F
