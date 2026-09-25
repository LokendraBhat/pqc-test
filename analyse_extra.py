#!/usr/bin/env python3
"""
analyze_extra.py - follow-up analyses that need the RAW data (latency_raw.csv).
Fills the red \\pend{} items in chapter-4.tex.

  1. Drift-corrected loopback comparisons (removes the shared slow drift that
     caused lag-1 autocorrelation of 0.7-0.85): residual = latency - rolling
     median of ALL runs in time order, then Welch + TOST as before.
  2. Bootstrap 95% CIs of median differences (key exchange and ML-DSA cost), all profiles.
  3. Tail share: fraction of handshakes above 1 s per cell (retransmission timeouts).
Usage: python3 analyze_extra.py latency_raw.csv --outdir results_extra [--window 41] [--boot 5000]
"""
import argparse, itertools, os
import numpy as np, pandas as pd
from scipy import stats

GROUPS = ["X25519", "P-256", "X25519MLKEM768", "SecP256r1MLKEM768"]
SHORT = {"X25519": "X", "P-256": "P", "X25519MLKEM768": "H", "SecP256r1MLKEM768": "H2"}


def run_index(s):
    # run_id is "<profile>-<k>" for measured runs, k = position in the interleaved sequence
    return pd.to_numeric(s.str.rsplit("-", n=1).str[-1], errors="coerce")


def welch_tost(x, y, margin, alpha=0.05):
    v1, v2 = x.var(ddof=1) / len(x), y.var(ddof=1) / len(y)
    se = np.sqrt(v1 + v2); df = (v1 + v2) ** 2 / (v1**2 / (len(x) - 1) + v2**2 / (len(y) - 1))
    diff = x.mean() - y.mean(); tc = stats.t.ppf(1 - alpha / 2, df)
    p = 2 * stats.t.sf(abs(diff / se), df)
    p_tost = max(stats.t.sf((diff + margin) / se, df), stats.t.cdf((diff - margin) / se, df))
    return diff, diff - tc * se, diff + tc * se, p, p_tost


def boot_median_diff(x, y, B, rng):
    bx = rng.choice(x, (B, len(x))); by = rng.choice(y, (B, len(y)))
    d = np.median(bx, 1) - np.median(by, 1)
    return np.median(x) - np.median(y), *np.percentile(d, [2.5, 97.5])


def holm(p):
    p = np.asarray(p, float); m = len(p); out = np.empty(m); run = 0
    for r, i in enumerate(np.argsort(p)):
        run = max(run, (m - r) * p[i]); out[i] = min(1, run)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default="latency_raw.csv")
    ap.add_argument("--outdir", default="results_extra")
    ap.add_argument("--window", type=int, default=41)
    ap.add_argument("--boot", type=int, default=5000)
    ap.add_argument("--margin", type=float, default=5.0)
    a = ap.parse_args(); os.makedirs(a.outdir, exist_ok=True)
    rng = np.random.default_rng(20260924)
    df = pd.read_csv(a.csv); df = df[(df.phase == "measure") & (df.ok == 1)].copy()
    df["k"] = run_index(df.run_id.astype(str))

    # 1. drift-corrected loopback
    lb = df[df.profile == "loopback"].sort_values("k").copy()
    trend = lb.latency_ms.rolling(a.window, center=True, min_periods=5).median()
    lb["resid"] = lb.latency_ms - trend + lb.latency_ms.median()
    lag = []
    for (au, g), s in lb.groupby(["auth", "group"]):
        x, r = s.latency_ms.to_numpy(), s.resid.to_numpy()
        lag.append(dict(auth=au, group=g, lag1_raw=np.corrcoef(x[:-1], x[1:])[0, 1],
                        lag1_corrected=np.corrcoef(r[:-1], r[1:])[0, 1]))
    lag = pd.DataFrame(lag); print("\n1a. Lag-1 autocorrelation before/after drift correction (loopback)")
    print(lag.round(2).to_string(index=False))
    rows = []
    for au in ["ecdsa", "mldsa"]:
        for g1, g2 in itertools.combinations(GROUPS, 2):
            x = lb[(lb.auth == au) & (lb.group == g1)].resid.to_numpy(); y = lb[(lb.auth == au) & (lb.group == g2)].resid.to_numpy()
            if len(x) > 2 and len(y) > 2:
                d, lo, hi, p, pt = welch_tost(x, y, a.margin)
                rows.append(dict(family="kx:" + au, comparison=f"{SHORT[g1]} vs. {SHORT[g2]}", diff=d, ci_low=lo, ci_high=hi, p=p, p_tost=pt))
    for g in GROUPS:
        x = lb[(lb.auth == "mldsa") & (lb.group == g)].resid.to_numpy(); y = lb[(lb.auth == "ecdsa") & (lb.group == g)].resid.to_numpy()
        if len(x) > 2 and len(y) > 2:
            d, lo, hi, p, pt = welch_tost(x, y, a.margin)
            rows.append(dict(family="auth", comparison=g, diff=d, ci_low=lo, ci_high=hi, p=p, p_tost=pt))
    dc = pd.DataFrame(rows); dc["p_holm"] = dc.groupby("family").p.transform(lambda s: holm(s))
    print("\n1b. Drift-corrected loopback comparisons (Welch on residuals)")
    print(dc.round(4).to_string(index=False)); dc.to_csv(f"{a.outdir}/loopback_drift_corrected.csv", index=False)

    # 2. bootstrap median differences
    bm = []
    for prof, d in df.groupby("profile", sort=False):
        for au in ["ecdsa", "mldsa"]:
            for g1, g2 in itertools.combinations(GROUPS, 2):
                x = d[(d.auth == au) & (d.group == g1)].latency_ms.to_numpy(); y = d[(d.auth == au) & (d.group == g2)].latency_ms.to_numpy()
                if len(x) and len(y):
                    m, lo, hi = boot_median_diff(x, y, a.boot, rng)
                    bm.append(dict(profile=prof, family="kx:" + au, comparison=f"{SHORT[g1]} vs. {SHORT[g2]}", median_diff=m, ci_low=lo, ci_high=hi))
        for g in GROUPS:
            x = d[(d.auth == "mldsa") & (d.group == g)].latency_ms.to_numpy(); y = d[(d.auth == "ecdsa") & (d.group == g)].latency_ms.to_numpy()
            if len(x) and len(y):
                m, lo, hi = boot_median_diff(x, y, a.boot, rng)
                bm.append(dict(profile=prof, family="auth", comparison=g, median_diff=m, ci_low=lo, ci_high=hi))
    bm = pd.DataFrame(bm); print("\n2. Bootstrap 95% CI of median differences (ML-DSA cost rows)")
    print(bm[bm.family == "auth"].round(1).to_string(index=False)); bm.to_csv(f"{a.outdir}/bootstrap_median.csv", index=False)

    # 3. tail share
    t = df.groupby(["profile", "auth", "group"], sort=False).latency_ms.agg(
        n="size", over_1s=lambda s: (s > 1000).sum()).reset_index()
    t["share_over_1s"] = t.over_1s / t.n
    print("\n3. Handshakes above 1 s per cell"); print(t.to_string(index=False))
    t.to_csv(f"{a.outdir}/tail_over_1s.csv", index=False)
    print(f"\nWritten to {a.outdir}/")


if __name__ == "__main__":
    main()
