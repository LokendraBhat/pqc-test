#!/usr/bin/env bash
# capture_handshakes.sh - packet captures of single TLS 1.3 handshakes over the emulated link,
# for the thesis timeline figure (ECDSA vs ML-DSA-65, same key exchange).
#
# What it does:
#   * sets netem to a clean profile (default 150 ms RTT, 0 % loss) so no retransmission hides the pattern
#   * turns off segmentation offloads on the veth pair so the capture shows real 1,448-byte segments
#   * captures on the CLIENT side (v-cli inside namespace cli) = what the client actually receives
#   * runs REPS handshakes per auth type, with a TLS key log so Wireshark can decrypt the Certificate messages
#   * restores the previous netem settings at the end
#
# Usage:  ./capture_handshakes.sh            (defaults: DELAY=75ms per direction, REPS=3)
#         DELAY=25ms ./capture_handshakes.sh (50 ms RTT)
set -u
DELAY=${DELAY:-75ms}; REPS=${REPS:-3}; OUT=${OUT:-/root/caps}; CA=${CA:-/root/pqc-bench-ca}
GROUP=${GROUP:-X25519MLKEM768}; IP=10.9.0.1; SNI=pqc.example.com
mkdir -p "$OUT"
command -v tcpdump >/dev/null || { echo "install tcpdump"; exit 1; }
command -v ethtool >/dev/null || { echo "install ethtool (dnf install ethtool)"; exit 1; }

old_srv=$(tc qdisc show dev v-srv | sed -n 's/.*netem [0-9a-f]*: root refcnt [0-9]* limit [0-9]* //p')
old_cli=$(ip netns exec cli tc qdisc show dev v-cli | sed -n 's/.*netem [0-9a-f]*: root refcnt [0-9]* limit [0-9]* //p')
echo "previous netem: v-srv [$old_srv]  v-cli [$old_cli]"

tc qdisc change dev v-srv root netem delay "$DELAY" loss 0%
ip netns exec cli tc qdisc change dev v-cli root netem delay "$DELAY" loss 0%
ethtool -K v-srv tso off gso off gro off >/dev/null 2>&1
ip netns exec cli ethtool -K v-cli tso off gso off gro off >/dev/null 2>&1
ip netns exec cli ping -c 5 -q $IP | tail -1

for spec in "ecdsa:443:ecdsa_secp256r1_sha256" "mldsa:8443:mldsa65"; do
  IFS=: read -r auth port sig <<< "$spec"
  pcap="$OUT/cap_${auth}_rtt$(( ${DELAY%ms} * 2 ))ms.pcap"; keys="$OUT/keys_${auth}.txt"; rm -f "$keys"
  ip netns exec cli tcpdump -i v-cli -s 0 -w "$pcap" "tcp port $port" >/dev/null 2>&1 &
  tpid=$!; sleep 1
  for ((i=1;i<=REPS;i++)); do
    t0=$(date +%s%N)
    ip netns exec cli bash -c "echo Q | openssl s_client -connect $IP:$port -servername $SNI -groups $GROUP \
        -sigalgs $sig -tls1_3 -CAfile $CA/$auth/root.crt -verify_return_error -keylogfile $keys \
        -provider default 2>&1" | grep -E "Negotiated TLS1.3 group|Peer signature type|has read|Verify return" | tr '\n' ' '
    echo "  -> $(( ($(date +%s%N)-t0)/1000000 )) ms"
    sleep 2                                   # gap so handshakes are easy to tell apart
  done
  sleep 1; kill $tpid; wait $tpid 2>/dev/null
  echo "saved $pcap  (key log: $keys)"
done

# restore
[ -n "$old_srv" ] && tc qdisc change dev v-srv root netem $old_srv
[ -n "$old_cli" ] && ip netns exec cli tc qdisc change dev v-cli root netem $old_cli
echo "restored netem. Offloads stay off until reboot (harmless for the benchmark)."
ls -l "$OUT"
