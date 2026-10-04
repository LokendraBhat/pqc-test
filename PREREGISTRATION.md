# Pre-registration: Post-Quantum TLS 1.3 on Real Internet Paths and Across Web-Server Stacks

**Author:** Lokendra Bhat
**Registered:** [date of the commit that adds this file]
**Status:** Registered before any data collection for this follow-up study.
**Builds on:** the thesis *Quantum-Safe TLS in Practice: Cost, Cause and Correct Configuration of Post-Quantum Key Exchange and Certificates*. Its emulated-network results (experiments E1–E4) are prior work and are not re-analysed here.

---

## 1. Background and motivation

The thesis found, on a single host with an emulated network, that:

- hybrid ML-KEM key exchange adds no practically significant latency;
- an ML-DSA-65 certificate chain adds about one round trip on wide-area paths, because the server flight exceeds TCP's ten-segment initial congestion window, and an ML-DSA-44 chain or a 20-segment initial window removes it;
- with a single-list group configuration in nginx/OpenSSL, a client that supports the hybrid but sends only a classical key share silently receives classical key exchange, while a separate hybrid preference tuple prevents this.

The main limitations were the emulated network and the single server implementation. This follow-up tests whether the findings hold on **real Internet paths** and across **different web-server stacks**.

## 2. Research questions

- **RQ-A (real paths):** Does the ML-DSA initial-window round trip occur on real Internet paths of different lengths from Nepal, and do the two remedies still remove it?
- **RQ-B (server stacks):** Do common web-server stacks negotiate classical key exchange with a client that supports the hybrid group but sends only a classical key share, under default and hybrid-enforcing configurations?
- **RQ-C (path MTU):** Does the path MTU of a real last-mile connection change the number of segments in the server flight, and therefore where the size threshold falls?

## 3. Hypotheses

| ID | Hypothesis | Prediction |
|---|---|---|
| HA1 | Hybrid ML-KEM key exchange adds no practically significant latency on real paths | Median difference vs classical below 0.1 × minimum RTT in every region |
| HA2 | An ML-DSA-65 chain adds about one RTT on real paths | Minimum-latency shift between 0.8 and 1.2 × minimum RTT in every region |
| HA3 | An ML-DSA-44 chain does not add a round trip | Minimum-latency shift below 0.2 × minimum RTT vs ECDSA |
| HA4 | An initial window of 20 segments removes the ML-DSA-65 round trip | Minimum-latency shift below 0.2 × minimum RTT vs ECDSA |
| HB1 | At least one widely used server stack, in its default configuration, gives classical key exchange to a client that supports the hybrid but sends only a classical key share | Observed in at least one stack |
| HB2 | Each tested stack has a configuration that enforces the hybrid for such a client, at the cost of one HelloRetryRequest | Hybrid negotiated with two ClientHellos |
| HC1 | If the path MTU is below 1,500 bytes, the ML-DSA-65 flight needs more segments than on the emulated 1,500-byte link | Segment count in the capture exceeds 12 |

The thresholds in HA1–HA4 are stated as fractions of the measured round-trip time because absolute latency on real paths varies with distance and time of day.

## 4. Design

### 4.1 Servers

- 2–3 virtual private servers in different regions, for example Mumbai or Singapore (short path), Frankfurt (medium), and US East (long).
- Operating system: AlmaLinux 9. TLS library: OpenSSL 3.5.x. nginx built against it. Exact versions will be recorded.
- Three certificate chains of identical structure (root, intermediate, leaf), freshly generated per server: ECDSA P-256, ML-DSA-65, ML-DSA-44. They are served on ports 443, 8443 and 9443 with identical key-exchange configuration.
- For RQ-B, on one server: nginx (OpenSSL), Caddy (Go crypto/tls), and HAProxy or Apache httpd (OpenSSL), each with the ECDSA chain, on separate ports.
- Test ports accept connections only from the client's public IP address.

### 4.2 Client

- The existing AlmaLinux VM with OpenSSL 3.5.5, using a **bridged** network adapter (not NAT). It connects from a residential or office connection in Nepal; the ISP and access technology will be recorded.
- The same measurement scripts as in the thesis (`collect_samples.sh`, `preflight_check.sh`).

### 4.3 Factors and sample size

**R1 (RQ-A, RQ-C):**
- Key exchange: X25519, P-256, X25519MLKEM768, SecP256r1MLKEM768 (4 levels).
- Certificate chain: ECDSA, ML-DSA-65, ML-DSA-44 (3 levels).
- Region: 2–3. Time slot: morning, evening, night (3).
- 100 measured handshakes per cell after 10 warm-up handshakes, all cells of a run randomly interleaved.

**R2 (RQ-A):** ECDSA and ML-DSA-65 with X25519MLKEM768, initial window 20, one run per region, 100 handshakes per cell.

**R3 (RQ-B):** four client behaviours (hybrid only; X25519 key share first with hybrid supported; both key shares; classical only) × each server stack × two configurations (default, hybrid-enforcing). Each combination is repeated 5 times to confirm the result is deterministic. HelloRetryRequest cost is measured with 30 alternating pairs per stack in the enforcing configuration.

**Packet captures:** 3 handshakes per chain per region with a TLS key log, plus the initial-window-20 condition.

**Justification of n = 100:** in the thesis, 100 handshakes per cell gave loopback confidence intervals within ±1.6 ms and clearly separated one-RTT effects on emulated paths. Real paths are expected to be noisier, so robust, median-based statistics are primary.

### 4.4 Path characterisation

Before every run: 100 ICMP probes (minimum, mean and maximum RTT, loss), `mtr`, `tracepath` (path MTU), and the client interface MTU. These are stored alongside the latency data.

## 5. Outcomes

- **Primary:** the shift in minimum handshake latency in units of the measured minimum RTT (HA2–HA4); the median latency difference with a bootstrap 95 % confidence interval (HA1–HA4); the negotiated group and number of ClientHellos (HB1, HB2).
- **Secondary:** mean differences with Welch 95 % confidence intervals; share of handshakes slower than 1 s; handshake bytes; segment count of the server flight from captures (HC1); HelloRetryRequest cost.

## 6. Analysis plan

- **Validity filter:** a handshake is kept only if TLS 1.3 negotiated the requested group and the chain verified against the test root.
- **Comparisons:** within each region and time slot only. Absolute latencies are not compared across runs.
- **Tests:** Mann–Whitney U and bootstrap confidence intervals of median differences (primary, because real-path latency is skewed); Welch's t-test with 95 % confidence intervals (secondary); Cohen's d; Fisher's exact test for the share above 1 s.
- **Multiple comparisons:** Holm adjustment within each family (key-exchange comparisons per chain and run; chain comparisons per key exchange and run).
- **Equivalence (HA1):** two one-sided tests against a margin of ±0.1 × minimum RTT for that run.
- **Significance level:** α = 0.05.
- **Serial dependence:** lag-1 autocorrelation is reported per cell. If |r| > 0.2, a rolling-median drift correction is applied as in the thesis, and both raw and corrected results are reported.
- **RQ-B:** reported as a table (stack × configuration × client behaviour → negotiated group, HelloRetryRequest yes/no). Any non-deterministic outcome across the 5 repetitions is reported as such.

## 7. Exclusions and stopping rules

- A run is repeated, and the original kept and reported, if more than 5 % of its handshakes fail for reasons outside the experiment (for example a client network outage). The cause is logged.
- A region is dropped only if its server cannot be reached reliably; this will be reported.
- No data will be excluded after inspecting the results, except as defined above.

## 8. Deviations

Any change to this plan after data collection begins will be recorded in a "Deviations" section of the final report, with the reason and the date. Analyses added after seeing the data will be labelled exploratory.

## 9. Data, code and ethics

- Raw latency files, path logs, packet captures with key logs of the test connections, scripts and configurations will be published in the project repository. Private keys of the test PKIs will not be published.
- Only servers owned or rented by the author are tested. No third-party systems are probed.
- Test root certificates are removed from any browser after use, and the servers are deleted after the study.
