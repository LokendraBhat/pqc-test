#!/usr/bin/env python3
"""
analyze_stats.py - statistics for the (key exchange) x (authentication) TLS 1.3 study.

Input: latency_raw.csv from collect_samples.sh (phase=measure rows only are used).
For every network profile it reports:
  A. descriptive statistics per auth x group            -> Table 4.2 / Table 7
  B. key-exchange comparisons within each auth          -> Table 8
     Welch t, Welch-Satterthwaite df, 95% CI, Mann-Whitney U, Cohen's d,
     TOST equivalence (+/- margin), Bonferroni and Holm adjusted p
  C. authentication cost per group (ML-DSA minus ECDSA) -> new Table (auth cost)
     same statistics plus the handshake-byte difference
  D. lag-1 autocorrelation (independence check) and box plots
Usage:  python3 analyze_stats.py latency_raw.csv [--margin 5] [--alpha 0.05] [--outdir results]
Needs:  numpy scipy pandas matplotlib
"""
import argparse, itertools, os, sys
import numpy as np, pandas as pd
from scipy import stats

GROUP_ORDER = ["X25519", "P-256", "X25519MLKEM768", "SecP256r1MLKEM768", "MLKEM768"]
SHORT = {"X25519": "X", "P-256": "P", "X25519MLKEM768": "H", "SecP256r1MLKEM768": "H2", "MLKEM768": "K"}
AUTH_ORDER = ["ecdsa", "mldsa"]


def ordered(values, pref):
    v = list(dict.fromkeys(values))
    return [x for x in pref if x in v] + sorted(x for x in v if x not in pref)


def effect_label(d):
    a = abs(d)
    return "negligible" if a < .2 else "small" if a < .5 else "medium" if a < .8 else "large"


def holm(p):
    p = np.asarray(p, float); m = len(p); adj = np.empty(m); run = 0.0
    for r, i in enumerate(np.argsort(p)):
        run = max(run, (m - r) * p[i]); adj[i] = min(1.0, run)
    return adj


def compare(xa, xb, margin, alpha):
    """a minus b."""
    n1, n2 = len(xa), len(xb)
    m1, m2, s1, s2 = xa.mean(), xb.mean(), xa.std(ddof=1), xb.std(ddof=1)
    v1, v2 = s1**2 / n1, s2**2 / n2
    se = np.sqrt(v1 + v2)
    df = (v1 + v2) ** 2 / (v1**2 / (n1 - 1) + v2**2 / (n2 - 1))
    diff = m1 - m2
    t, p = stats.ttest_ind(xa, xb, equal_var=False)
    tc = stats.t.ppf(1 - alpha / 2, df)
    u, pmw = stats.mannwhitneyu(xa, xb, alternative="two-sided")
    p_tost = max(stats.t.sf((diff + margin) / se, df), stats.t.cdf((diff - margin) / se, df))
    d = diff / np.sqrt((s1**2 + s2**2) / 2)
    return dict(n_a=n1, n_b=n2, diff=diff, t=t, df=df, p_welch=p, ci_low=diff - tc * se,
                ci_high=diff + tc * se, U=u, p_mw=pmw, cohen_d=d, effect=effect_label(d),
                median_diff=np.median(xa) - np.median(xb), p_tost=p_tost)


def adjust(df, alpha, keys):
    if df.empty:
        return df
    out = []
    for _, g in df.groupby(keys, sort=False):
        g = g.copy(); k = len(g)
        g["p_welch_bonf"] = np.minimum(1, g.p_welch * k)
        g["p_welch_holm"] = holm(g.p_welch)
        g["p_mw_holm"] = holm(g.p_mw)
        g["significant_holm"] = g.p_welch_holm < alpha
        g["equivalent"] = g.p_tost < alpha
        out.append(g)
    return pd.concat(out)


def lag1(x):
    return float(np.corrcoef(x[:-1], x[1:])[0, 1]) if len(x) > 3 else np.nan


def descriptive(d):
    rows = []
    for (auth, grp), s in d.groupby(["auth", "group"], sort=False):
        ok = s[s.ok == 1]
        x = ok.latency_ms.to_numpy()   # rows are in collection (time) order
        if len(x) == 0:
            rows.append(dict(auth=auth, group=grp, n_ok=0, n_fail=len(s))); continue
        by = (pd.to_numeric(ok.bytes_read, errors="coerce") + pd.to_numeric(ok.bytes_written, errors="coerce"))
        rx = pd.to_numeric(s.get("client_retrans", pd.Series(dtype=float)), errors="coerce")
        rows.append(dict(auth=auth, group=grp, n_ok=len(x), n_fail=int((s.ok != 1).sum()),
                         mean=x.mean(), median=np.median(x), p95=np.percentile(x, 95), sd=x.std(ddof=1),
                         min=x.min(), max=x.max(), iqr=np.subtract(*np.percentile(x, [75, 25])),
                         skew=stats.skew(x), lag1=lag1(x), bytes_median=by.median(),
                         bytes_read=pd.to_numeric(ok.bytes_read, errors="coerce").median(),
                         retrans_per100=(rx.sum() / len(s) * 100) if rx.notna().any() else np.nan))
    out = pd.DataFrame(rows)
    ak = {x: i for i, x in enumerate(ordered(out.auth, AUTH_ORDER))}
    gk = {x: i for i, x in enumerate(ordered(out.group, GROUP_ORDER))}
    return out.sort_values(["auth", "group"], key=lambda c: c.map(ak if c.name == "auth" else gk)).reset_index(drop=True)


def fp(p):
    return "< 0.001" if p < 0.001 else f"{p:.3f}"


def show(df, title, cols):
    print(f"\n{title}")
    if df.empty:
        print("  (not enough data)"); return
    t = df[cols].copy()
    for c in t.columns:
        if c.startswith("p_"):
            t[c] = t[c].map(fp)
    print(t.round(2).to_string(index=False))


def latex_rows(df, label_col):
    return "\n".join(f"{r[label_col]} & {r.t:.2f} & {fp(r.p_welch_holm)} & {r.U:.0f} & {fp(r.p_mw_holm)} & "
                     f"{r.cohen_d:.2f} & {r.effect} & [{r.ci_low:.2f}, {r.ci_high:.2f}] \\\\"
                     for _, r in df.iterrows())


def boxplot(d, groups, auths, title, path):
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    except ImportError:
        return
    fig, ax = plt.subplots(figsize=(8, 4.2)); pos, data, ticks, labels = [], [], [], []
    for i, g in enumerate(groups):
        for j, a in enumerate(auths):
            x = d[(d.group == g) & (d.auth == a) & (d.ok == 1)].latency_ms
            if len(x):
                p = i * (len(auths) + 1) + j; pos.append(p); data.append(x)
        ticks.append(i * (len(auths) + 1) + (len(auths) - 1) / 2); labels.append(g)
    b = ax.boxplot(data, positions=pos, showmeans=True, patch_artist=True, widths=0.8)
    colors = ["#9ecae1", "#fdae6b", "#a1d99b"]
    k = 0
    for i, g in enumerate(groups):
        for j, a in enumerate(auths):
            if len(d[(d.group == g) & (d.auth == a) & (d.ok == 1)]):
                b["boxes"][k].set_facecolor(colors[j % 3]); k += 1
    ax.set_xticks(ticks, labels); ax.set_ylabel("Handshake latency (ms)"); ax.set_title(title)
    ax.legend([plt.Rectangle((0, 0), 1, 1, fc=colors[j % 3]) for j in range(len(auths))], auths, title="auth")
    ax.grid(axis="y", alpha=.3); fig.tight_layout(); fig.savefig(path, dpi=200); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default="latency_raw.csv")
    ap.add_argument("--margin", type=float, default=5.0)
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--outdir", default="results")
    a = ap.parse_args()
    if not os.path.exists(a.csv):
        sys.exit(f"{a.csv} not found")
    os.makedirs(a.outdir, exist_ok=True)
    df = pd.read_csv(a.csv)
    if "auth" not in df.columns:
        df["auth"] = "ecdsa"
    df = df[df.phase == "measure"]

    all_desc, all_kx, all_auth = [], [], []
    for profile, d in df.groupby("profile", sort=False):
        groups = ordered(d.group, GROUP_ORDER); auths = ordered(d.auth, AUTH_ORDER)
        print(f"\n==================== Profile: {profile} ====================")
        desc = descriptive(d); desc.insert(0, "profile", profile); all_desc.append(desc)
        show(desc, "A. Descriptive statistics", [c for c in ["auth", "group", "n_ok", "n_fail", "mean", "median", "p95",
             "sd", "min", "max", "skew", "lag1", "bytes_median", "retrans_per100"] if c in desc])
        if "lag1" in desc and (desc.lag1.abs() > 0.2).any():
            print("  NOTE: |lag-1 autocorrelation| > 0.2 in some cells - report as a limitation.")

        kx = []
        for au in auths:
            for g1, g2 in itertools.combinations(groups, 2):
                x1 = d[(d.auth == au) & (d.group == g1) & (d.ok == 1)].latency_ms.to_numpy()
                x2 = d[(d.auth == au) & (d.group == g2) & (d.ok == 1)].latency_ms.to_numpy()
                if len(x1) > 2 and len(x2) > 2:
                    kx.append(dict(profile=profile, auth=au, comparison=f"{SHORT.get(g1, g1)} vs. {SHORT.get(g2, g2)}",
                                   **compare(x1, x2, a.margin, a.alpha)))
        kx = adjust(pd.DataFrame(kx), a.alpha, ["profile", "auth"]); all_kx.append(kx)
        show(kx, f"B. Key-exchange comparisons within each auth (Holm-adjusted; TOST margin +/-{a.margin} ms)",
             ["auth", "comparison", "diff", "ci_low", "ci_high", "t", "df", "p_welch_holm", "U", "p_mw_holm",
              "cohen_d", "effect", "p_tost"] if not kx.empty else [])

        au_rows = []
        if {"ecdsa", "mldsa"} <= set(auths):
            for g in groups:
                x1 = d[(d.auth == "mldsa") & (d.group == g) & (d.ok == 1)]
                x2 = d[(d.auth == "ecdsa") & (d.group == g) & (d.ok == 1)]
                if len(x1) > 2 and len(x2) > 2:
                    r = compare(x1.latency_ms.to_numpy(), x2.latency_ms.to_numpy(), a.margin, a.alpha)
                    b1 = (pd.to_numeric(x1.bytes_read, errors="coerce") + pd.to_numeric(x1.bytes_written, errors="coerce")).median()
                    b2 = (pd.to_numeric(x2.bytes_read, errors="coerce") + pd.to_numeric(x2.bytes_written, errors="coerce")).median()
                    au_rows.append(dict(profile=profile, group=g, **r, bytes_mldsa=b1, bytes_ecdsa=b2, bytes_added=b1 - b2))
        au = adjust(pd.DataFrame(au_rows), a.alpha, ["profile"]); all_auth.append(au)
        show(au, "C. Authentication cost: ML-DSA-65 minus ECDSA P-256 (Holm-adjusted across groups)",
             ["group", "diff", "ci_low", "ci_high", "median_diff", "p_welch_holm", "p_mw_holm", "cohen_d", "effect",
              "bytes_ecdsa", "bytes_mldsa", "bytes_added"] if not au.empty else [])

        tag = str(profile).replace("/", "_").replace("%", "pct")
        boxplot(d, groups, auths, f"TLS 1.3 handshake latency - {profile}", f"{a.outdir}/boxplot_{tag}.png")
        with open(f"{a.outdir}/latex_rows_{tag}.tex", "w") as f:
            if not kx.empty:
                for au_name, g in kx.groupby("auth", sort=False):
                    f.write(f"% Table 8 rows, auth={au_name}: Comparison & t & p_Holm(Welch) & U & p_Holm(M-W) & d & Effect & 95% CI\n")
                    f.write(latex_rows(g, "comparison") + "\n")
            if not au.empty:
                f.write("% Auth-cost rows: Group & t & p_Holm(Welch) & U & p_Holm(M-W) & d & Effect & 95% CI\n")
                f.write(latex_rows(au, "group") + "\n")

    pd.concat(all_desc).to_csv(f"{a.outdir}/descriptive.csv", index=False)
    pd.concat(all_kx).to_csv(f"{a.outdir}/kx_comparisons.csv", index=False)
    if any(not x.empty for x in all_auth):
        pd.concat(all_auth).to_csv(f"{a.outdir}/auth_cost.csv", index=False)
    print(f"\nWritten to {a.outdir}/: descriptive.csv, kx_comparisons.csv, auth_cost.csv, latex_rows_*.tex, boxplot_*.png")


if __name__ == "__main__":
    main()
