# Capturing and Analysing Post-Quantum TLS Handshakes with Wireshark

A practical guide for this study: how to capture TLS 1.3 handshakes on the test VM or a remote server, decrypt them with a key log, and read the evidence for each finding — negotiated group, key-share sizes, certificate and signature sizes, the initial-window pause, HelloRetryRequest and retransmissions.

> Field names below are from recent Wireshark releases (4.x). If a filter is rejected, click the field in the packet details pane, then right-click → **Apply as Filter → Selected** to get the exact name for your version.

---

## 1. Tools

| Tool | Where | Purpose |
|---|---|---|
| `tcpdump` | Server / VM (no GUI) | Record packets to a `.pcap` file |
| `openssl s_client -keylogfile` | Client | Write TLS secrets so Wireshark can decrypt |
| Wireshark | Your desktop (Ubuntu host) | Inspect and visualise captures |
| `tshark` | VM / server | Command-line Wireshark for scripted checks |

Install on AlmaLinux: `dnf install -y tcpdump wireshark-cli`
Install on Ubuntu: `sudo apt install wireshark tshark`

---

## 2. Capturing

### 2.1 Get realistic packets

Network offloads make the capture show merged "super-packets" instead of the real 1,448-byte segments. Turn them off on the capture interface (restored at reboot):

```bash
ethtool -K <iface> tso off gso off gro off
```

For the emulated testbed, apply this to both `v-srv` and (inside the namespace) `v-cli`. For real-path tests, apply it on the client's network interface.

### 2.2 Start the capture

Capture on the **client side** — it shows what the client actually receives and when.

```bash
# Emulated testbed (client inside namespace cli)
ip netns exec cli tcpdump -i v-cli -s 0 -w cap_mldsa65.pcap 'tcp port 8443' &

# Real path (client VM, remote server)
tcpdump -i <client-iface> -s 0 -w cap_real_mldsa65.pcap 'host <server-ip> and tcp port 8443' &
```

### 2.3 Make the handshake, with a key log

```bash
echo Q | openssl s_client -connect <server>:8443 -servername pqc.example.com \
  -groups X25519MLKEM768 -sigalgs mldsa65 -tls1_3 \
  -CAfile <path>/mldsa/root.crt -verify_return_error \
  -keylogfile keys_mldsa65.txt -provider default
sleep 2; kill %1
```

Make one handshake per capture file (or leave a few seconds between handshakes) so they are easy to tell apart.

### 2.4 Capturing a browser

On the computer running the browser:

```bash
export SSLKEYLOGFILE=$HOME/browser_keys.txt     # set BEFORE starting the browser
google-chrome &                                  # or brave-browser
sudo tcpdump -i <iface> -s 0 -w cap_browser.pcap 'tcp port 443 or tcp port 8443'
```

> **Security:** while `SSLKEYLOGFILE` is set, the browser records secrets for *every* site you visit. Browse only the test server, then close the browser, `unset SSLKEYLOGFILE` and delete the file.

### 2.5 Copy files to your desktop

```bash
scp root@<vm-or-server>:/root/caps/{cap_*.pcap,keys_*.txt} ~/captures/
```

---

## 3. Opening and decrypting

1. **File → Open** the `.pcap`.
2. **Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename** → choose the matching `keys_*.txt`.
3. Click **OK**. Encrypted handshake records (EncryptedExtensions, Certificate, CertificateVerify, Finished) now appear decrypted.

Without the key log, everything after the ServerHello is shown only as "Application Data" of known length — still enough for size and timing analysis, but not for certificate details.

**Useful view settings**

- **View → Time Display Format → Seconds Since Beginning of Capture** (or *Since Previous Displayed Packet* to see gaps).
- Add columns: right-click a field → **Apply as Column** (e.g. `tcp.len`, `tls.handshake.type`).

---

## 4. Reference values for this study

### TLS group code points (`supported_groups`, `key_share`)

| Code (hex) | Code (decimal) | Group |
|---|---|---|
| 0x001d | 29 | X25519 |
| 0x0017 | 23 | secp256r1 (P-256) |
| 0x11ec | 4588 | X25519MLKEM768 |
| 0x11eb | 4587 | SecP256r1MLKEM768 |

### Signature algorithms

| Code | Algorithm |
|---|---|
| 0x0403 | ecdsa_secp256r1_sha256 |
| 0x0904 | mldsa44 |
| 0x0905 | mldsa65 |
| 0x0906 | mldsa87 |

### Expected sizes (from the thesis)

| Item | Bytes |
|---|---|
| X25519MLKEM768 client key share | 1,216 |
| X25519MLKEM768 server key share | 1,120 |
| ECDSA server flight (hybrid KEX) | 2,380 |
| ML-DSA-65 server flight (hybrid KEX) | 15,867 |
| ML-DSA-44 server flight (hybrid KEX) | 11,926 |

### HelloRetryRequest marker

A HelloRetryRequest is a ServerHello whose `random` field equals this fixed value:

```
cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c
```

---

## 5. Display filters — one per question

| What you want to see | Display filter |
|---|---|
| All TLS handshake messages | `tls.handshake` |
| ClientHello only | `tls.handshake.type == 1` |
| ServerHello (and HRR) only | `tls.handshake.type == 2` |
| Handshakes where the hybrid was chosen | `tls.handshake.type == 2 && tls.handshake.extensions_key_share_group == 0x11ec` |
| Silent classical fallback (server picked X25519) | `tls.handshake.type == 2 && tls.handshake.extensions_key_share_group == 0x001d` |
| HelloRetryRequest | `tls.handshake.type == 2 && tls.handshake.random == cf:21:ad:74:e5:9a:61:11:be:1d:8c:02:1e:65:b8:91:c2:a2:11:16:7a:bb:8c:5e:07:9e:09:e2:c8:a8:33:9c` |
| Clients offering ML-DSA | `tls.handshake.sig_hash_alg == 0x0905` |
| Certificate message (decrypted) | `tls.handshake.type == 11` |
| CertificateVerify (decrypted) | `tls.handshake.type == 15` |
| Server data segments only | `tcp.srcport == 8443 && tcp.len > 0` |
| Retransmissions | `tcp.analysis.retransmission \|\| tcp.analysis.fast_retransmission` |
| One connection only | `tcp.stream == 0` (change the number) |

---

## 6. Analyses step by step

### 6.1 Which group was negotiated? (correctness, silent fallback)

1. Filter `tls.handshake.type == 2`.
2. Expand **Transport Layer Security → Handshake Protocol: Server Hello → Extension: key_share → Key Share Entry**.
3. Read **Group** (e.g. `X25519MLKEM768 (4588)`) and **Key Exchange Length** (expect 1,120 for the hybrid).

For the client side, filter `tls.handshake.type == 1` and expand **supported_groups** (what the client supports) and **key_share** (which groups it already sent a key for, with their lengths — 1,216 for X25519MLKEM768, 32 for X25519).

**Silent fallback** is visible when the ClientHello lists `X25519MLKEM768` in *supported_groups*, sends only an X25519 *key_share*, and the ServerHello selects `X25519`.

### 6.2 Was there a HelloRetryRequest? (cost of enforcing the hybrid)

- Apply the HRR filter from §5, or simply count ClientHellos in one stream: `tcp.stream == 0 && tls.handshake.type == 1`. Two ClientHellos = one retry.
- Measure its cost: select the first ClientHello, then the second; the time difference (with *Seconds Since Previous Displayed Packet*) is about one RTT.

### 6.3 How big is each handshake message? (cost)

With the key log loaded:

1. Filter `tcp.srcport == 8443 && tls`.
2. In each record, expand the handshake message and read **Length**:
   - **Certificate** (type 11) — the chain; ~930 B with ECDSA, ~11,179 B with ML-DSA-65.
   - **CertificateVerify** (type 15) — the signature; ~79 B with ECDSA, ~3,317 B with ML-DSA-65.
3. **Statistics → Conversations → TCP** shows total bytes in each direction per connection.

### 6.4 Did the flight overflow the initial window? (cause)

This is the key evidence for the extra round trip.

1. Filter `tcp.srcport == 8443 && tcp.len > 0` (server data segments).
2. Set **View → Time Display Format → Seconds Since Previous Displayed Packet**.
3. Count the segments and look at the time column:
   - **ECDSA:** 2 segments, then nothing — no pause.
   - **ML-DSA-65:** 10 segments arrive together, then a **gap of about one RTT**, then the last 2 segments.
4. Confirm the cause: just before the gap you will see the **client's ACK** leave (`tcp.dstport == 8443 && tcp.flags.ack == 1 && tcp.len == 0`); the remaining segments arrive one one-way delay later.

**Graph it:** select a server data packet → **Statistics → TCP Stream Graphs → Stevens** (sequence number vs time). The ML-DSA-65 flight shows a staircase with a flat step of one RTT; the ECDSA flight is a single jump. With **initcwnd 20** or **ML-DSA-44**, the step disappears.

**Check the segment size (path MTU, RQ-C):** look at `tcp.len` of full segments. On a 1,500-byte path with timestamps it is 1,448; on a PPPoE path it is smaller (e.g. ~1,440 or less), so ten segments hold fewer bytes and the threshold moves.

### 6.5 Did anything get lost? (tail latency)

- Filter `tcp.analysis.retransmission || tcp.analysis.fast_retransmission`.
- **Analyze → Expert Information** lists retransmissions, duplicate ACKs and out-of-order packets.
- A handshake slower than 1 s usually shows a retransmission timeout here.

### 6.6 Real round-trip time from the capture

- `tcp.analysis.ack_rtt` gives the time from a segment to its ACK. Add it as a column and read it for the SYN/SYN-ACK pair.
- Or: time between the client's **SYN** and the server's **SYN-ACK** in the client-side capture = one RTT.

### 6.7 Browser behaviour (client readiness)

In the browser capture's ClientHello:

- **supported_groups:** is `X25519MLKEM768` first? (GREASE values like `0x?a?a` are random placeholders — ignore them.)
- **key_share:** does it carry both X25519MLKEM768 (1,216 B) and X25519?
- **signature_algorithms:** are `mldsa44/65/87` listed before ECDSA/RSA?
- **ClientHello length** (`tls.handshake.length`): more than one TCP segment?

In the ServerHello: which group did the server pick, and was there an HRR?

---

## 7. Command-line equivalents (tshark)

Useful on the VM or for repeatable numbers in the thesis.

```bash
# Negotiated group per connection
tshark -r cap.pcap -Y "tls.handshake.type == 2" \
  -T fields -e tcp.stream -e tls.handshake.extensions_key_share_group

# Server data segments with time since previous segment (initial-window pause)
tshark -r cap.pcap -Y "tcp.srcport == 8443 && tcp.len > 0" \
  -T fields -e frame.number -e frame.time_delta_displayed -e tcp.len

# Decrypted handshake message types and lengths (needs key log)
tshark -r cap.pcap -o tls.keylog_file:keys_mldsa65.txt \
  -Y "tls.handshake" -T fields -e frame.number -e tls.handshake.type -e tls.handshake.length

# Count ClientHellos per stream (2 = HelloRetryRequest)
tshark -r cap.pcap -Y "tls.handshake.type == 1" -T fields -e tcp.stream | sort | uniq -c

# Retransmissions
tshark -r cap.pcap -Y "tcp.analysis.retransmission || tcp.analysis.fast_retransmission" | wc -l
```

---

## 8. Exporting evidence for the thesis or paper

- **Figures:** Stevens graph → **Save As** PNG; or export packet data (**File → Export Packet Dissections → As CSV**) and plot it yourself, as done for the thesis timeline figure.
- **Tables:** **Statistics → Conversations** or tshark output (§7) pasted into a table.
- **Single packets:** **File → Export Specified Packets** to keep a small, shareable pcap for the repository.
- **Reproducibility:** store each pcap with its key log, the command used, the network profile and the date.

---

## 9. Checklist per capture

- [ ] Offloads disabled on the capture interface
- [ ] One handshake per file (or clearly separated)
- [ ] `-keylogfile` written and stored next to the pcap
- [ ] Negotiated group and signature algorithm confirmed (§6.1)
- [ ] Server-flight segment count and pause recorded (§6.4)
- [ ] Retransmissions checked (§6.5)
- [ ] Path RTT and segment size noted (§6.4, §6.6)
- [ ] Browser key-log file deleted after browser captures
