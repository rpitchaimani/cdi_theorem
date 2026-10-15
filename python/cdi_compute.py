#!/usr/bin/env python3
"""
cdi_compute.py — CDI capacity computation (Theorem 6.4)

Implements (Option B, per-window units):
    c(G, j)   = sum_i (1-Gamma_i_eff) * sum_k theta_ik_eff(j) * m_ik * rho_ik   [bits per window]
    C_<=n     = sum_{s=1..n} c(G, j(s))                                         [bits by deadline n]
    T_min     = (H(phi) - 1) / c_bar * T_w                                       [minimum dwell time]
  m_ik  : sampling coverage, fraction of the window's reports produced (0..1)
  rho_ik: richness, reports per window x entropy per report (bits per window)
  xi terms are kept in the data model but default to 0 (union bound, Remark ass:corr).

Usage:
    python cdi_compute.py                  # run built-in 11-system audit
    python cdi_compute.py --uart ids.txt   # parse hardware UART log

References: Theorem 6.4, Tables 5-8 of the paper.
"""
import argparse, math, sys
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Partition:
    name: str
    theta: List[float]   # theta_ik(ell_j) for each narrative step j=0..n_steps-1
    m:     float         # sampling coverage: fraction of the window's reports produced (0-1)
    rho:   float         # richness: reports per window x entropy per report (bits per window)


@dataclass
class Node:
    name: str
    Gamma:       float           # platform trust gap
    Gamma_cross: float = 0.0    # cross-domain leakage
    partitions:  List[Partition] = field(default_factory=list)
    xi:          float = 0.0    # intra-node redundancy


def gamma_eff(node: Node) -> float:
    return 1.0 - (1.0 - node.Gamma) * (1.0 - node.Gamma_cross)


def cdi_capacity(nodes: List[Node], j: int, xi_inter: float = 0.0) -> float:
    """
    Compute C_CDI(G, j) for narrative step j.
    Returns capacity in bits (>= 0).
    """
    total = 0.0
    for node in nodes:
        g = gamma_eff(node)
        psum = sum(
            p.theta[j] * p.m * p.rho
            for p in node.partitions
            if j < len(p.theta)
        )
        total += (1.0 - g) * max(0.0, psum - node.xi)
    return max(0.0, total - xi_inter)


T_W = 0.1  # detection window length in seconds (100 ms, Section 9)


def cumulative_capacity(nodes: List[Node], schedule: List[int]) -> float:
    """C_<=n: sum of per-window capacity over windows s=1..n, where schedule[s-1] = j(s)."""
    return sum(cdi_capacity(nodes, j) for j in schedule)


def t_min(c_bar: float, H_phi: float, T_w: float = T_W) -> float:
    """Minimum dwell time (s) before blinding needed for task entropy H_phi (Corollary cor:dwell).
    Returns inf when the per-window capacity is zero."""
    if c_bar <= 0:
        return math.inf
    return max(0.0, H_phi - 1.0) / c_bar * T_w


def fmt_time(t: float) -> str:
    if math.isinf(t):
        return "never"
    for lim, div, unit in ((60, 1, "s"), (3600, 60, "min"), (86400, 3600, "h")):
        if t < lim:
            return f"{t/div:.1f} {unit}"
    return f"{t/86400:.1f} d"


def print_tmin_table(tasks):
    """tasks: list of (label, H_phi). Uses per-window capacity at j=0 (before escalation) as c_bar."""
    hdr = "".join(f"{lbl:>16}" for lbl, _ in tasks)
    print(f"\n{'System':<14} {'c (b/window)':>13}{hdr}")
    print("-" * (28 + 16 * len(tasks)))
    for name, node in SYSTEMS.items():
        c = cdi_capacity([node], j=0)
        cells = "".join(f"{fmt_time(t_min(c, H)):>16}" for _, H in tasks)
        print(f"{name:<14} {c:>13.4f}{cells}")


# ---------------------------------------------------------------------------
# Miller-Madow entropy estimator (matches C firmware Q5.3 implementation)
# ---------------------------------------------------------------------------

def miller_madow(counts: List[int]) -> float:
    """
    H_MM = H_MLE + (k_hat - 1) / (2*N)
    counts: histogram bucket counts
    Returns entropy in bits.
    """
    N = sum(counts)
    if N == 0:
        return 0.0
    k_hat = sum(1 for c in counts if c > 0)
    h_mle = -sum((c / N) * math.log2(c / N) for c in counts if c > 0)
    return h_mle + (k_hat - 1) / (2.0 * N)


# ---------------------------------------------------------------------------
# Paper system definitions (Tables 5-8, Table 1)
# ---------------------------------------------------------------------------

H_V = 12.88  # bits: Leaf chain IA-PES-C2-LM-IMP, ATM v4.02 scoped to the threat model (hv_atm.py)

# Narrative steps: j=0 (pre-attack) .. j=3 (post-LM)
# theta[j] values from Table 6 / Section 7

SYSTEMS = {
    "SAIDuCANT": Node("SAIDuCANT", Gamma=0.760, partitions=[
        Partition("unknown", theta=[0.05]*4, m=0.0, rho=0.013)]),
    "VoltageIDS": Node("VoltageIDS", Gamma=0.052, partitions=[
        Partition("physical", theta=[1.0, 1.0, 0.05, 0.05], m=0.5, rho=5.1)]),
    "AE-TW": Node("AE-TW", Gamma=0.760, partitions=[
        Partition("HLOS", theta=[0.05]*4, m=0.0, rho=0.007)]),
    "CAE/LSTMAE": Node("CAE/LSTMAE", Gamma=0.760, partitions=[
        Partition("GPU", theta=[0.05]*4, m=0.0, rho=0.0)]),
    "Multi-GRU": Node("Multi-GRU", Gamma=0.760, partitions=[
        Partition("HLOS", theta=[0.05]*4, m=0.05, rho=2.93)]),
    "CLAM": Node("CLAM", Gamma=0.760, partitions=[
        Partition("XPU", theta=[0.05]*4, m=0.0, rho=0.0)]),
    "E-GAN": Node("E-GAN", Gamma=0.52, partitions=[
        Partition("FPGA", theta=[0.50]*4, m=0.20, rho=3.08)]),
    "H-IDFS": Node("H-IDFS", Gamma=0.52, partitions=[
        Partition("unknown", theta=[0.30]*4, m=0.08, rho=0.185)]),
    "Auto-CIDS": Node("Auto-CIDS", Gamma=0.760, partitions=[
        Partition("GPU", theta=[0.05]*4, m=0.0, rho=0.010)]),
    "LATTE": Node("LATTE", Gamma=0.760, partitions=[
        Partition("HLOS", theta=[0.05]*4, m=0.05, rho=0.010)]),
    "PHIDIAS": Node("PHIDIAS", Gamma=0.052, partitions=[
        Partition("BM", theta=[1.0, 1.0, 0.05, 0.05], m=1.0, rho=0.001)]),
}

# PoC configurations (Section 9)
POC_BASELINE = [Node("MPC5748G_baseline", Gamma=0.052, partitions=[
    Partition("BM_IDS", theta=[0.95, 0.95, 0.12, 0.12], m=1.0, rho=12.5)])]

POC_MITIGATED = [Node("MPC5748G_G1G4", Gamma=0.052, partitions=[
    Partition("BM_IDS", theta=[0.99, 0.99, 0.99, 0.99], m=1.0, rho=15.2)])]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def print_audit_table():
    print(f"\n{'System':<14} {'C_CDI_best':>12} {'C_CDI_worst':>13} {'C/H(V)':>8}  {'Feasible?'}")
    print("-" * 60)
    for name, node in SYSTEMS.items():
        # best-case: j=0 (no escalation)
        best  = cdi_capacity([node], j=0)
        # worst-case: j=3 (post-LM)
        worst = cdi_capacity([node], j=3)
        ratio = best / H_V if H_V > 0 else 0
        flag  = "YES" if best >= H_V - 1 else "no"  # one-window check against the Fano bar H(V)-1
        print(f"{name:<14} {best:>12.4f} {worst:>13.4f} {ratio:>8.3f}  {flag}")
    print(f"\nH(V) = {H_V} bits; one-window Fano bar H(V)-1 = {H_V-1:.1f} bits (necessary, not sufficient)")


def parse_uart_log(path: str):
    """
    Parse IDS UART log produced by core1_ids.c.
    Lines match: [IDS] #N t=T  pkts=P  ...  H=E  CCDI=C  PHASE
    Returns list of (window, entropy_fp, ccdi, phase) tuples.
    """
    import re
    results = []
    pat = re.compile(r'\[IDS\] #(\d+).*H=(\d+).*CCDI=([\d.]+)\s+(\w+)')
    try:
        with open(path) as f:
            for line in f:
                m = pat.search(line)
                if m:
                    win   = int(m.group(1))
                    h_fp  = int(m.group(2))          # Q5.3 fixed-point (/ 8 = bits)
                    ccdi  = float(m.group(3))
                    phase = m.group(4)
                    results.append((win, h_fp / 8.0, ccdi, phase))
    except FileNotFoundError:
        print(f"[warn] log file not found: {path}", file=sys.stderr)
    return results


def print_uart_summary(records):
    if not records:
        print("No IDS records parsed.")
        return
    print(f"\n{'Win':>5} {'H(bits)':>9} {'C_CDI':>8}  Phase")
    print("-" * 35)
    for win, h, ccdi, phase in records[:50]:
        marker = " *** BLIND" if ccdi < 1.0 and phase not in ("NONE",) else ""
        print(f"{win:>5} {h:>9.3f} {ccdi:>8.3f}  {phase}{marker}")
    if len(records) > 50:
        print(f"  ... {len(records)-50} more windows")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CDI capacity computation (Theorem 6.4)")
    parser.add_argument("--uart", metavar="FILE",
                        help="Parse hardware UART IDS log from core1_ids.c")
    parser.add_argument("--system", metavar="NAME",
                        help=f"Compute for one system: {list(SYSTEMS)}")
    parser.add_argument("--step", type=int, default=0, metavar="J",
                        help="Narrative step j (0=pre-attack, 3=post-LM)")
    args = parser.parse_args()

    if args.uart:
        print(f"Parsing UART log: {args.uart}")
        records = parse_uart_log(args.uart)
        print_uart_summary(records)
        return

    if args.system:
        if args.system not in SYSTEMS:
            print(f"Unknown system '{args.system}'. Choose from: {list(SYSTEMS)}")
            sys.exit(1)
        node = SYSTEMS[args.system]
        for j in range(4):
            c = cdi_capacity([node], j)
            print(f"  j={j}: C_CDI = {c:.4f} bits  (H(V)={H_V}, ratio={c/H_V:.3f})")
        return

    # Default: full audit table
    print("=" * 60)
    print("CDI Capacity Audit — 11 Automotive IDS Systems")
    print("Theorem 6.4 | H(V) = {:.1f} bits".format(H_V))
    print("=" * 60)
    print_audit_table()

    # Minimum dwell time (Corollary cor:dwell). PROVISIONAL: H(V)=11.3 is pending recomputation on
    # ATM v4.02, and most systems' m and rho have not yet been re-derived in per-window units.
    H_IMP = math.log2(8)          # single-stage bar: |A(Affect Vehicle Function)| = 8 in ATM v4.02
    tasks = [("single-stage", H_IMP), ("prefix<impact", H_V - H_IMP), ("full narrative", H_V)]
    print("\n--- Minimum dwell time before blinding (PROVISIONAL) ---")
    print_tmin_table(tasks)

    print("\n--- PoC configurations ---")
    for label, nodes in [("Baseline (θ=0.95, ρ=12.5 b, j=0)", POC_BASELINE),
                          ("Post-τ_LM (θ=0.12, j=3)",          POC_BASELINE),
                          ("Mitigated G1-G4 (θ=0.99, ρ=15.2 b)", POC_MITIGATED)]:
        j = 3 if "Post" in label else 0
        c = cdi_capacity(nodes, j)
        print(f"  {label}: C_CDI = {c:.4f} bits")


if __name__ == "__main__":
    main()
