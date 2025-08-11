#!/usr/bin/env python3
# bench_all.py  — Verkle/Merkle Benchmark Suite (5 Experiments)
import os, sys, csv, gc, random, time, tracemalloc, argparse
from statistics import median
import importlib
import pippenger as pip
import hashlib

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

# ---------- utils ----------
def set_seed(seed: int):
    random.seed(seed)
    try:
        import numpy as np
        np.random.seed(seed)
    except Exception:
        pass

class Timer:
    def __enter__(self):
        gc.collect()
        tracemalloc.start()
        self.t0 = time.perf_counter()
        return self
    def __exit__(self, *exc):
        self.t1 = time.perf_counter()
        self.mem_peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    @property
    def sec(self): return self.t1 - self.t0
    @property
    def mem_kb(self): return self.mem_peak / 1024.0

def rand_bytes32():
    upper = (1 << 256) - 1
    return random.randint(0, upper).to_bytes(32, "little")

def ensure_dir(path: str):
    """Create parent dir for file path OR the dir itself if path is a dir."""
    if not path:
        return
    # if path looks like a file (has extension), create its parent
    directory = os.path.dirname(path) if os.path.splitext(path)[1] else path
    if directory == "":
        directory = "."
    os.makedirs(directory, exist_ok=True)

# =========================
# Verkle (with multiproof)
# =========================
def _reload_verkle_with_width_bits(width_bits: int):
    os.environ["VERKLE_WIDTH_BITS"] = str(width_bits)
    import verkle as vk
    importlib.reload(vk)
    return vk

def _proof_size_bytes(proof) -> int:
    s = sum(len(c) for c in proof.commitsSortedByIndex)
    s += len(proof.polySerialised) + len(proof.compressedMultiProof)
    ch = proof.challenge
    if isinstance(ch, int):
        s += (ch.bit_length() + 7) // 8 or 1
    elif isinstance(ch, bytes):
        s += len(ch)
    return s

def _build_tree(vk, n: int):
    tree = vk.VerkleTree()
    values = {}
    keys = []
    with Timer() as t_build:
        for _ in range(n):
            k = rand_bytes32()
            v = rand_bytes32()
            tree.insert(tree.root, k, v)
            keys.append(k)
            values[k] = v
    with Timer() as t_root:
        vk.add_node_hash(tree.root)
    return tree, keys, values, t_build, t_root

def _gen_and_verify(vk, tree, keys, values, k: int):
    sel = keys[:k] if len(keys) >= k else keys
    with Timer() as t_proof:
        proof = tree.make_verkle_proof(tree, sel)
    psize = _proof_size_bytes(proof)
    with Timer() as t_verify:
        ok = tree.check_verkle_proof(
            tree.root.commitment.compress(),
            sel,
            [values[k] for k in sel],
            proof
        )
    return proof, psize, t_proof, t_verify, ok

def _aggregate_median(rows):
    num_keys = ["build_s", "build_mem_kb", "root_s", "root_mem_kb",
                "proof_s", "proof_mem_kb", "verify_s", "verify_mem_kb", "proof_size_bytes"]
    out = dict(rows[0])
    for k in num_keys:
        out[k] = median(r[k] for r in rows)
    out["verify_ok"] = all(r["verify_ok"] for r in rows)
    return out

def cmd_verkle(args):
    ensure_dir(args.out)
    fieldnames = ["width_bits", "n", "k", "mode",
                  "build_s", "build_mem_kb", "root_s", "root_mem_kb",
                  "proof_s", "proof_mem_kb", "verify_s", "verify_mem_kb",
                  "proof_size_bytes", "verify_ok","compute_s"]
    rows_all = []
    for wb in args.width_bits:
        vk = _reload_verkle_with_width_bits(wb)
        print(f"[info] verkle loaded from: {vk.__file__}")
        for n in args.n:
            for k in args.k:
                for use_naive in ([False, True] if args.compare_naive else [False]):
                    runs = []
                    orig = pip.pippenger_simple
                    if use_naive:
                        if not hasattr(pip, "lincomb_naive"):
                            import blst
                            def _g1_zero():
                                try: return blst.G1().mult(0)
                                except AttributeError: return blst.P1().mult(0)
                            def lincomb_naive(group_elements, factors):
                                assert len(group_elements) == len(factors)
                                acc = _g1_zero()
                                for g, f in zip(group_elements, factors):
                                    acc = acc.add(g.dup().mult(int(f)))
                                return acc
                            pip.lincomb_naive = lincomb_naive
                        pip.pippenger_simple = pip.lincomb_naive
                    try:
                        for rep in range(args.repeats):
                            seed = (args.seed or 2025) + rep
                            set_seed(seed)
                            print(f"[run] wb={wb} n={n} k={k} mode={'naive' if use_naive else 'pippenger'} rep={rep + 1}/{args.repeats}")
                            tree, keys, values, t_build, t_root = _build_tree(vk, n)
                            proof, psize, t_proof, t_verify, ok = _gen_and_verify(vk, tree, keys, values, k)
                            row = {
                                "width_bits": wb, "n": n, "k": k,
                                "mode": "naive" if use_naive else "pippenger",
                                "build_s": t_build.sec, "build_mem_kb": t_build.mem_kb,
                                "root_s": t_root.sec, "root_mem_kb": t_root.mem_kb,
                                "proof_s": t_proof.sec, "proof_mem_kb": t_proof.mem_kb,
                                "verify_s": t_verify.sec, "verify_mem_kb": t_verify.mem_kb,
                                "proof_size_bytes": psize, "verify_ok": bool(ok),
                            }
                            print("   times(s): build={:.3f} root={:.3f} proof={:.3f} verify={:.3f} | size={}B | ok={}".format(
                                  row["build_s"], row["root_s"], row["proof_s"], row["verify_s"],
                                  row["proof_size_bytes"], row["verify_ok"]))
                            runs.append(row)
                    finally:
                        pip.pippenger_simple = orig
                    rows_all.append(_aggregate_median(runs))
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader(); w.writerows(rows_all)
    print(f"[done] wrote {args.out}")

# =========================
# Merkle baseline
# =========================
def _sha(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def _merkle_build(keys, values):
    leaves = [_sha(k + v) for k, v in zip(keys, values)]
    layers = [leaves]
    while len(layers[-1]) > 1:
        cur = layers[-1]; nxt = []
        for i in range(0, len(cur), 2):
            a = cur[i]; b = cur[i + 1] if i + 1 < len(cur) else a
            nxt.append(_sha(a + b))
        layers.append(nxt)
    return layers

def _merkle_prove(layers, idx):
    proof = []
    for layer in layers[:-1]:
        sib = idx ^ 1
        proof.append(layer[sib] if sib < len(layer) else layer[idx])
        idx //= 2
    return proof

def _merkle_verify(root, leaf, proof, idx):
    h = leaf
    for p in proof:
        h = _sha(h + p) if idx % 2 == 0 else _sha(p + h)
        idx //= 2
    return h == root

def cmd_merkle(args):
    ensure_dir(args.out)
    fieldnames = ["n", "k", "build_s", "prove_s", "verify_s", "avg_proof_size", "ok"]
    all_rows = []
    for k in args.k:
        reps = []
        for rep in range(args.repeats):
            seed = (args.seed or 2025) + rep
            set_seed(seed)
            keys = [rand_bytes32() for _ in range(args.n)]
            vals = [rand_bytes32() for _ in range(args.n)]
            t0 = time.perf_counter(); layers = _merkle_build(keys, vals); t1 = time.perf_counter()
            idxs = random.sample(range(args.n), min(k, args.n))
            t2 = time.perf_counter(); proofs = [_merkle_prove(layers, i) for i in idxs]; t3 = time.perf_counter()
            root = layers[-1][0]
            leaves = [_sha(keys[i] + vals[i]) for i in idxs]
            t4 = time.perf_counter(); oks = [_merkle_verify(root, leaf, pf, i) for leaf, pf, i in zip(leaves, proofs, idxs)]; t5 = time.perf_counter()
            reps.append({
                "n": args.n, "k": k,
                "build_s": t1 - t0, "prove_s": t3 - t2, "verify_s": t5 - t4,
                "avg_proof_size": sum(len(x) * 32 for x in proofs) / max(1, len(proofs)),
                "ok": all(oks),
            })
        agg = {fld: median(r[fld] for r in reps) for fld in ["build_s","prove_s","verify_s","avg_proof_size"]}
        agg.update({"n": args.n, "k": k, "ok": all(r["ok"] for r in reps)})
        all_rows.append(agg)
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader(); w.writerows(all_rows)
    print(f"[done] wrote {args.out}")

# =========================
# Plot helpers
# =========================
def _read_csv(path):
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        rows = []
        for row in r:
            rec = {}
            for k, v in row.items():
                if v is None: rec[k] = v; continue
                try:
                    rec[k] = float(v) if v.replace('.', '', 1).isdigit() else v
                except Exception:
                    rec[k] = v
            rows.append(rec)
        return rows

def cmd_plot(args):
    import matplotlib.pyplot as plt, os
    ensure_dir(args.out_proof)
    rows = _read_csv(args.verkle_csv)
    rows.sort(key=lambda r: (int(float(r.get("width_bits", 0))),
                             int(float(r.get("n", 0))),
                             int(float(r.get("k", 0)))))
    def plot_time_vs_k(metric, out_path):
        wb = args.width_bits
        subset = [r for r in rows if int(float(r.get("width_bits", -1))) == wb]
        if not subset:
            print(f"[warn] no rows for width_bits={wb}"); return
        plt.figure()
        groups = {}
        for r in subset:
            mode = str(r.get("mode", "pippenger"))
            nval = int(float(r.get("n", 0)))
            groups.setdefault((mode, nval), []).append(r)
        for (mode, nval), rs in sorted(groups.items()):
            rs.sort(key=lambda x: int(float(x["k"])))
            xs = [int(float(x["k"])) for x in rs]
            ys = [float(x[metric]) for x in rs]
            plt.plot(xs, ys, marker="o", label=f"{mode}, n={nval}")
        if args.merkle_csv and os.path.exists(args.merkle_csv):
            mrows = _read_csv(args.merkle_csv)
            if mrows:
                mrows.sort(key=lambda r: int(float(r["k"])))
                xs = [int(float(r["k"])) for r in mrows]
                m_metric = "prove_s" if metric == "proof_s" else "verify_s"
                ys = [float(r[m_metric]) for r in mrows]
                n_merkle = int(float(mrows[0]["n"]))
                plt.plot(xs, ys, marker="x", linestyle="--",
                         label=f"merkle ({m_metric}), n={n_merkle}")
        plt.xlabel("k (keys per proof)"); plt.ylabel(metric.replace("_", " "))
        plt.xscale("log"); plt.legend(); plt.tight_layout()
        plt.savefig(out_path, dpi=180); print(f"[saved] {out_path}")
    plot_time_vs_k("proof_s", args.out_proof)
    plot_time_vs_k("verify_s", args.out_verify)
    


def cmd_plot_wb(args):
    import matplotlib.pyplot as plt
    ensure_dir(args.out_proof)
    rows = _read_csv(args.verkle_csv)
    rows = [r for r in rows if str(r.get("mode","pippenger"))=="pippenger" and int(float(r.get("n",-1)))==args.n]
    if not rows:
        print(f"[warn] no rows for n={args.n} in {args.verkle_csv}"); return
    def _parse_lim(s):
        if not s: return None
        try:
            a,b = s.split(","); return (float(a), float(b))
        except Exception:
            print(f"[warn] bad ylim spec: {s} (expect 'min,max')"); return None
    ylim_proof = _parse_lim(getattr(args, "ylim_proof", ""))
    ylim_verify = _parse_lim(getattr(args, "ylim_verify", ""))
    wbs = sorted({int(float(r["width_bits"])) for r in rows})
    def _plot(metric, ylabel, out_path, yscale=None, to_kb=False, ylim=None):
        import matplotlib.pyplot as plt
        plt.figure()
        for wb in wbs:
            rs = [r for r in rows if int(float(r["width_bits"])) == wb]
            rs.sort(key=lambda x: int(float(x["k"])))
            xs = [int(float(x["k"])) for x in rs]
            ys = [float(x[metric]) for x in rs]
            if to_kb: ys = [y / 1024.0 for y in ys]
            plt.plot(xs, ys, marker="o", label=f"wb={wb}")
        plt.xlabel("k (keys per proof)"); plt.ylabel(ylabel); plt.xscale("log")
        if yscale: plt.yscale(yscale)
        if ylim: plt.ylim(*ylim)
        plt.legend(); plt.tight_layout(); plt.savefig(out_path, dpi=180)
        print(f"[saved] {out_path}")
    _plot("proof_s", "proof s", args.out_proof, ylim=ylim_proof)
    _plot("verify_s", "verify s", args.out_verify, ylim=ylim_verify)
    if args.out_size:
        _plot("proof_size_bytes", "proof size (KB)", args.out_size, to_kb=True)

# ----- new: time vs n (fixed wb,k)
def cmd_plot_n(args):
    import matplotlib.pyplot as plt, numpy as np, os
    ensure_dir(args.out_dir)
    rows = _read_csv(args.verkle_csv)
    rows = [r for r in rows if str(r.get("mode","pippenger"))=="pippenger"
            and int(float(r.get("width_bits",-1)))==args.width_bits
            and int(float(r.get("k",-1)))==args.k]
    if not rows:
        print(f"[warn] no rows for wb={args.width_bits}, k={args.k} in {args.verkle_csv}"); return
    rows.sort(key=lambda r: int(float(r["n"])))
    xs = np.array([int(float(r["n"])) for r in rows], dtype=float)
    for metric, fname in [("proof_s","time_vs_n_proof.png"), ("verify_s","time_vs_n_verify.png")]:
        ys = np.array([float(r[metric]) for r in rows], dtype=float)
        plt.figure(); plt.plot(xs, ys, marker="o")
        plt.xscale("log"); plt.yscale("log")
        if len(xs) >= 2 and (xs>0).all() and (ys>0).all():
            alpha, c = np.polyfit(np.log(xs), np.log(ys), 1)
            plt.title(f"{metric} (~ n^{alpha:.2f})")
        plt.xlabel("n (initial keys)"); plt.ylabel(metric.replace("_"," "))
        plt.tight_layout(); outp = os.path.join(args.out_dir, fname)
        plt.savefig(outp, dpi=180); print(f"[saved] {outp}")

# ----- new: proof size vs k
def cmd_plot_size(args):
    import matplotlib.pyplot as plt, os
    ensure_dir(args.out)
    rows = _read_csv(args.verkle_csv)
    rows = [r for r in rows if str(r.get("mode","pippenger"))=="pippenger"
            and int(float(r.get("width_bits",-1)))==args.width_bits]
    if not rows:
        print(f"[warn] no rows for width_bits={args.width_bits} in {args.verkle_csv}"); return
    groups = {}
    for r in rows:
        nval = int(float(r["n"])); groups.setdefault(nval, []).append(r)
    import matplotlib.pyplot as plt
    plt.figure()
    for nval, rs in sorted(groups.items()):
        rs.sort(key=lambda x: int(float(x["k"])))
        xs = [int(float(x["k"])) for x in rs]
        ys = [float(x["proof_size_bytes"])/1024.0 for x in rs]
        plt.plot(xs, ys, marker="o", label=f"n={nval}")
    plt.xscale("log"); plt.xlabel("k (keys per proof)"); plt.ylabel("proof size (KB)")
    plt.legend(); plt.tight_layout(); plt.savefig(args.out, dpi=180)
    print(f"[saved] {args.out}")

# ----- new: compare two CSVs (ours vs eth) time vs k
def _read_rows_filtered_k(csv_path, wb, n):
    rows = _read_csv(csv_path)
    rows = [r for r in rows if str(r.get("mode","pippenger"))=="pippenger"
            and int(float(r.get("width_bits",-1)))==wb
            and int(float(r.get("n",-1)))==n]
    rows.sort(key=lambda r: int(float(r["k"])))
    xs = [int(float(r["k"])) for r in rows]
    proof = [float(r["proof_s"]) for r in rows]
    verify = [float(r["verify_s"]) for r in rows]
    return xs, proof, verify

def cmd_plot_total(args):
    import matplotlib.pyplot as plt
    import math

    def read_csv(path):
        import csv
        rows = []
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                rows.append(r)
        return rows

    def to_float(x, default=None):
        try:
            return float(x)
        except Exception:
            return default

    plt.figure()

    # --- Verkle (多 wb 支持) ---
    v_rows_all = read_csv(args.verkle_csv)
    for wb in args.width_bits:
        v_rows = [r for r in v_rows_all
                  if int(r.get("width_bits", -1)) == wb
                  and r.get("mode", "") == args.mode
                  and (args.n is None or int(r.get("n", -1)) == args.n)]
        if not v_rows:
            print(f"[warn] no rows for wb={wb}")
            continue
        # k -> list of compute_s
        v_bucket = {}
        for r in v_rows:
            k = int(r["k"])
            cs = to_float(r.get("compute_s"))
            if cs is None:  # 兼容旧CSV
                cs = sum(to_float(r.get(f), 0.0) for f in ("build_s", "root_s", "proof_s", "verify_s"))
            v_bucket.setdefault(k, []).append(cs)
        v_x = sorted(v_bucket)
        v_y = [sorted(v_bucket[k])[len(v_bucket[k]) // 2] for k in v_x]  # median
        plt.plot(v_x, v_y, marker="o", label=f"Verkle wb={wb}")

    # --- Merkle (可选) ---
    if args.merkle_csv:
        m_rows = read_csv(args.merkle_csv)
        m_bucket = {}
        for r in m_rows:
            k = int(r["k"])
            cs = to_float(r.get("compute_s"))
            if cs is None:
                cs = sum(to_float(r.get(f), 0.0) for f in ("build_s", "prove_s", "verify_s"))
            m_bucket.setdefault(k, []).append(cs)
        if m_bucket:
            m_x = sorted(m_bucket)
            m_y = [sorted(m_bucket[k])[len(m_bucket[k]) // 2] for k in m_x]
            plt.plot(m_x, m_y, linestyle="--", marker="x", label="Merkle")

    # --- Ethereum Verkle (可选) ---
    if args.eth_csv:
        e_rows = read_csv(args.eth_csv)
        e_bucket = {}
        for r in e_rows:
            k = int(r["k"])
            cs = to_float(r.get("compute_s") or r.get("total_s") or r.get("time_s"))
            if cs is not None:
                e_bucket.setdefault(k, []).append(cs)
        if e_bucket:
            e_x = sorted(e_bucket)
            e_y = [sorted(e_bucket[k])[len(e_bucket[k]) // 2] for k in e_x]
            plt.plot(e_x, e_y, linestyle=":", marker="s", label="Ethereum Verkle")

    plt.xscale("log")
    plt.xlabel("k (keys per proof, log scale)")
    plt.ylabel("Total compute time (s)")
    plt.grid(True, which="both", linestyle=":")
    plt.legend()
    ensure_dir(args.out)
    plt.savefig(args.out, bbox_inches="tight")
    print(f"[ok] saved {args.out}")

def cmd_compare_k(args):
    import matplotlib.pyplot as plt, os
    ensure_dir(args.out_dir)
    xs_a, p_a, v_a = _read_rows_filtered_k(args.verkle_csv_a, args.width_bits, args.n)
    xs_b, p_b, v_b = _read_rows_filtered_k(args.verkle_csv_b, args.width_bits, args.n)
    def plot_one(xa, ya, xb, yb, ylabel, fname):
        import matplotlib.pyplot as plt
        plt.figure()
        if xa: plt.plot(xa, ya, marker="o", label=args.label_a)
        if xb: plt.plot(xb, yb, marker="x", linestyle="--", label=args.label_b)
        plt.xscale("log"); plt.xlabel("k (keys per proof)"); plt.ylabel(ylabel)
        plt.legend(); plt.tight_layout()
        outp = os.path.join(args.out_dir, fname); plt.savefig(outp, dpi=180)
        print(f"[saved] {outp}")
    plot_one(xs_a, p_a, xs_b, p_b, "proof s",  "compare_time_vs_k_proof.png")
    plot_one(xs_a, v_a, xs_b, v_b, "verify s", "compare_time_vs_k_verify.png")

# =========================
# Suite runner + summary
# =========================
def _ns(**kw):
    class NS: pass
    o = NS()
    for k,v in kw.items(): setattr(o,k,v)
    return o

def _summarize(bench_csv, merkle_csv=None, width_bits_focus=8, n_focus=16384):
    import math
    rows = _read_csv(bench_csv)
    if not rows:
        print("[summary] no rows found."); return
    # focus subset
    wb_rows = [r for r in rows if int(float(r.get("width_bits",-1)))==width_bits_focus and str(r.get("mode","pippenger"))=="pippenger"]
    n_rows = [r for r in wb_rows if int(float(r.get("n",-1)))==n_focus]
    # size checkpoints
    def _find_sz(k):
        cand = [r for r in n_rows if int(float(r["k"]))==k]
        return (float(cand[0]["proof_size_bytes"])/1024.0) if cand else None
    s100, s1k, s5k = _find_sz(100), _find_sz(1000), _find_sz(5000)
    # wb effect at a few k
    def _wb_delta(k):
        by_wb = {}
        for r in rows:
            if int(float(r.get("k",-1)))==k and str(r.get("mode","pippenger"))=="pippenger" and int(float(r.get("n",-1)))==n_focus:
                by_wb[int(float(r["width_bits"]))] = float(r["proof_s"])
        if len(by_wb)>=2:
            mn = min(by_wb.values()); mx = max(by_wb.values())
            return mn, mx, (mx-mn)/mx*100.0, by_wb
        return None
    d1 = _wb_delta(1); d100 = _wb_delta(100); d1k = _wb_delta(1000)
    print("\n========= SUMMARY (auto) =========")
    print(f"Focus: wb={width_bits_focus}, n={n_focus}")
    if s100 is not None: print(f"Proof size @k=100  ~ {s100:.1f} KB")
    if s1k  is not None: print(f"Proof size @k=1000 ~ {s1k:.1f} KB")
    if s5k  is not None: print(f"Proof size @k=5000 ~ {s5k:.1f} KB")
    for tag, d in [("k=1",d1), ("k=100",d100), ("k=1000",d1k)]:
        if d:
            mn,mx,delta,table = d
            print(f"wb effect {tag}: spread ≈ {delta:.1f}%  (seconds per proof: {table})")
    if merkle_csv and os.path.exists(merkle_csv):
        mrows = _read_csv(merkle_csv)
        if mrows:
            # report merkle prove_s at n_focus if present
            mk = [int(float(r["k"])) for r in mrows if int(float(r["n"]))==n_focus]
            ms = [(int(float(r["k"])), float(r["prove_s"])) for r in mrows if int(float(r["n"]))==n_focus]
            if ms:
                ms.sort()
                print("Merkle baseline prove_s (n={}): {}".format(n_focus, dict(ms)))
    print("==================================\n")

def cmd_suite(args):
    """Run 5 experiments end-to-end and summarize."""
    out_dir = os.path.join(ROOT, "results"); ensure_dir(out_dir)
    bench_csv = os.path.join(out_dir, "bench.csv")
    merkle_csv = os.path.join(out_dir, "merkle.csv")

    # Choose scale
    if args.full:
        width_bits = [4,8,16]
        ns = [1024, 4096, 16384, 65536]
        ks = [1, 100, 1000, 5000]
        repeats = 3
    else:
        width_bits = [4,8,16]
        ns = [4096, 16384]
        ks = [1, 100, 1000, 5000]
        repeats = 1

    # EXP A + B + C (single comprehensive run to populate bench.csv)
    print("\n[SUITE] Running Verkle benchmarks …")
    cmd_verkle(_ns(width_bits=width_bits, n=ns, k=ks, repeats=repeats,
                   seed=2025, out=bench_csv, compare_naive=False))

    # EXP Merkle baseline (for overlay in A)
    if args.run_merkle:
        print("\n[SUITE] Running Merkle baseline …")
        cmd_merkle(_ns(n=16384, k=ks, repeats=repeats, seed=2025, out=merkle_csv))
    else:
        merkle_csv = None

    # EXP A: time vs k (wb focus)
    print("\n[SUITE] Plot: time vs k (Exp A) …")
    cmd_plot(_ns(verkle_csv=bench_csv, merkle_csv=merkle_csv, width_bits=args.wb_focus,
                  out_proof=os.path.join(out_dir, "plot_proof_time.png"),
                  out_verify=os.path.join(out_dir, "plot_verify_time.png")))

    # EXP B + C: width_bits comparison at fixed n (time & size)
    print("\n[SUITE] Plot: width-bits compare (Exp C) …")
    cmd_plot_wb(_ns(verkle_csv=bench_csv, n=args.n_focus,
                     out_proof=os.path.join(out_dir, "plot_wb_proof.png"),
                     out_verify=os.path.join(out_dir, "plot_wb_verify.png"),
                     out_size=os.path.join(out_dir, "plot_wb_size.png"),
                     ylim_proof="", ylim_verify=""))

    # EXP B: time vs n (fixed wb,k)
    print("\n[SUITE] Plot: time vs n (Exp B) …")
    cmd_plot_n(_ns(verkle_csv=bench_csv, width_bits=args.wb_focus, k=args.k_focus,
                    out_dir=out_dir))

    # EXP D: proof size vs k
    print("\n[SUITE] Plot: proof size vs k (Exp D) …")
    cmd_plot_size(_ns(verkle_csv=bench_csv, width_bits=args.wb_focus,
                       out=os.path.join(out_dir, "plot_size_vs_k.png")))

    # EXP E: ours vs ethereum (optional, if csv provided)
    if args.eth_csv and os.path.exists(args.eth_csv):
        print("\n[SUITE] Compare ours vs ETH (Exp E) …")
        cmd_compare_k(_ns(verkle_csv_a=bench_csv, verkle_csv_b=args.eth_csv,
                          label_a="ours", label_b="eth",
                          width_bits=args.wb_focus, n=args.n_focus,
                          out_dir=out_dir))
    else:
        print("\n[SUITE] Skipping Exp E (no --eth-csv provided or file not found).")

    # Summary
    _summarize(bench_csv, merkle_csv=merkle_csv,
               width_bits_focus=args.wb_focus, n_focus=args.n_focus)
    print("[SUITE] Done. Figures & CSV in:", out_dir)

# =========================
# CLI
# =========================
def main():
    # If run without args, default to 'suite' quick mode
    if len(sys.argv) == 1:
        sys.argv.append("suite")

    if "--total" in sys.argv:
        sys.argv = [
            sys.argv[0],
            "plot-total",
            "--verkle-csv", "results/bench.csv",
            "--merkle-csv", "results/merkle.csv",
            "--width-bits", "4", "8", "16",
            "--out", "results/plot_total_multi_wb.png"
        ]

    ap = argparse.ArgumentParser(description="Verkle/Merkle benchmarking & plotting (all-in-one)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_v = sub.add_parser("verkle", help="run verkle benchmarks")
    ap_v.add_argument("--width-bits", nargs="+", type=int, default=[8], help="e.g., 4 8 16")
    ap_v.add_argument("--n", nargs="+", type=int, default=[2 ** 12, 2 ** 14], help="num initial keys")
    ap_v.add_argument("--k", nargs="+", type=int, default=[1, 100, 1000, 5000], help="keys per proof")
    ap_v.add_argument("--repeats", type=int, default=3)
    ap_v.add_argument("--seed", type=int, default=2025)
    ap_v.add_argument("--out", default=os.path.join(ROOT, "results", "bench.csv"))
    ap_v.add_argument("--compare-naive", action="store_true", help="also run naive lincomb baseline (slow)")
    ap_v.set_defaults(func=cmd_verkle)

    ap_m = sub.add_parser("merkle", help="run merkle baseline")
    ap_m.add_argument("--n", type=int, default=16384)
    ap_m.add_argument("--k", nargs="+", type=int, default=[1000])  # multiple k
    ap_m.add_argument("--repeats", type=int, default=3)
    ap_m.add_argument("--seed", type=int, default=2025)
    ap_m.add_argument("--out", default=os.path.join(ROOT, "results", "merkle.csv"))
    ap_m.set_defaults(func=cmd_merkle)

    ap_p = sub.add_parser("plot", help="plot time vs k from csv")
    ap_p.add_argument("--verkle-csv", default=os.path.join(ROOT, "results", "bench.csv"))
    ap_p.add_argument("--merkle-csv", default=os.path.join(ROOT, "results", "merkle.csv"))
    ap_p.add_argument("--width-bits", type=int, default=8)
    ap_p.add_argument("--out-proof", default=os.path.join(ROOT, "results", "plot_proof_time.png"))
    ap_p.add_argument("--out-verify", default=os.path.join(ROOT, "results", "plot_verify_time.png"))
    ap_p.set_defaults(func=cmd_plot)

    ap_wb = sub.add_parser("plot-wb", help="plot Verkle curves across width_bits at fixed n")
    ap_wb.add_argument("--verkle-csv", default=os.path.join(ROOT, "results", "bench.csv"))
    ap_wb.add_argument("--n", type=int, default=16384)
    ap_wb.add_argument("--out-proof", default=os.path.join(ROOT, "results", "plot_wb_proof.png"))
    ap_wb.add_argument("--out-verify", default=os.path.join(ROOT, "results", "plot_wb_verify.png"))
    ap_wb.add_argument("--out-size", default=os.path.join(ROOT, "results", "plot_wb_size.png"))
    ap_wb.add_argument("--ylim-proof", default="", help="y-limits for proof plot, e.g. 0.3,1.2")
    ap_wb.add_argument("--ylim-verify", default="", help="y-limits for verify plot, e.g. 0.02,0.12")
    ap_wb.set_defaults(func=cmd_plot_wb)

    ap_n = sub.add_parser("plot-n", help="plot time vs n at fixed (width_bits, k)")
    ap_n.add_argument("--verkle-csv", default=os.path.join(ROOT, "results", "bench.csv"))
    ap_n.add_argument("--width-bits", type=int, default=8)
    ap_n.add_argument("--k", type=int, default=1000)
    ap_n.add_argument("--out-dir", default=os.path.join(ROOT, "results"))
    ap_n.set_defaults(func=cmd_plot_n)

    ap_sz = sub.add_parser("plot-size", help="plot proof size (KB) vs k at fixed width_bits")
    ap_sz.add_argument("--verkle-csv", default=os.path.join(ROOT, "results", "bench.csv"))
    ap_sz.add_argument("--width-bits", type=int, default=8)
    ap_sz.add_argument("--out", default=os.path.join(ROOT, "results", "plot_size_vs_k.png"))
    ap_sz.set_defaults(func=cmd_plot_size)

    ap_ck = sub.add_parser("compare-k", help="compare time vs k across two CSVs at fixed (width_bits, n)")
    ap_ck.add_argument("--verkle-csv-a", required=True)
    ap_ck.add_argument("--verkle-csv-b", required=True)
    ap_ck.add_argument("--label-a", default="ours")
    ap_ck.add_argument("--label-b", default="eth")
    ap_ck.add_argument("--width-bits", type=int, default=8)
    ap_ck.add_argument("--n", type=int, default=16384)
    ap_ck.add_argument("--out-dir", default=os.path.join(ROOT, "results"))
    ap_ck.set_defaults(func=cmd_compare_k)

    ap_s = sub.add_parser("suite", help="run all 5 experiments and summarize")
    ap_s.add_argument("--full", action="store_true", help="full scale (slower). default: quick mode")
    ap_s.add_argument("--run-merkle", action="store_true", help="also run Merkle baseline for overlay in Exp A")
    ap_s.add_argument("--eth-csv", default="", help="optional: path to ETH implementation bench.csv for Exp E")
    ap_s.add_argument("--wb-focus", type=int, default=8, help="focus width_bits for plots A/B/D/E")
    ap_s.add_argument("--n-focus", type=int, default=16384, help="focus n for plots C/E & summary")
    ap_s.add_argument("--k-focus", type=int, default=1000, help="focus k for plot-n")
    ap_s.set_defaults(func=cmd_suite)
    
    p = sub.add_parser("plot-total", help="Plot proof/verify time vs k (multi width_bits)")
    p.add_argument("--verkle-csv", required=True)
    p.add_argument("--merkle-csv")               # merkle
    p.add_argument("--eth-csv")                  # eth
    p.add_argument("--width-bits", type=int, nargs="+", required=True)
    p.add_argument("--n", type=int, help="filter by n when plotting Verkle (optional)")
    p.add_argument("--mode", default="pippenger")
    p.add_argument("--out", default="results/plot_total.png")
    p.set_defaults(func=cmd_plot_total)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
