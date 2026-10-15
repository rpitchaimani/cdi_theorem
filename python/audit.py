#!/usr/bin/env python3
"""audit.py: per-system capacity and minimum dwell time from audit_worksheet.csv.

Usage:
    python audit.py [audit_worksheet.csv]

Per window (T_w), a partition delivers at most m * rho = min(n, U*T_w/latency) * h bits,
where n is reports per window, h = log2(classes) bounds the entropy of one report,
and U is the CPU share the monitor may use. This is an upper bound, so it favors
the detector. theta and Gamma use the pre-blinding values (authentic, platform intact),
which also favors the detector. Rows without a latency stay unresolved; nothing is guessed.

Task entropies come from hv_atm.py (ATM v4.02, scoped to the threat model).
A system that never observes a stage cannot learn its technique (Corollary cor:coverage),
so a task that includes an unobserved stage is out of reach at any dwell time.
"""
import csv
import math
import sys

T_W = 0.1      # detection window, s
U = 0.015      # monitoring CPU share (1.5% of one core), same for every system

# Scoped per-stage technique entropies, bits (hv_atm.py, ATM v4.02)
H_STAGE = {"IA": math.log2(5), "EX": math.log2(3), "PES": math.log2(7),
           "C2": math.log2(6), "LM": math.log2(6), "IMP": math.log2(6)}
PREFIX = ["IA", "PES", "C2", "LM"]          # steps before impact in the running example


def fmt(t):
    if t is None:
        return "unresolved"
    if math.isinf(t):
        return "never"
    if t < 1:
        return f"{t*1000:.0f} ms"
    if t < 60:
        return f"{t:.1f} s"
    if t < 3600:
        return f"{t/60:.1f} min"
    return f"{t/3600:.1f} h"


def per_window_bits(row):
    """Upper bound on m*rho for one partition, or None if latency is missing."""
    if not row["latency_s"] or not row["classes"]:
        return None
    lat = float(row["latency_s"])
    h = math.log2(int(row["classes"]))
    budget_reports = U * T_W / lat
    n = float(row["events_per_s"]) * T_W if row["events_per_s"] else budget_reports
    return min(n, budget_reports) * h


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "audit_worksheet.csv"
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    print(f"T_w = {T_W*1000:.0f} ms, CPU share U = {U:.1%}\n")
    print(f"{'System':<12} {'stages':<8} {'c (b/window)':>13} {'T_min single stage':>19} "
          f"{'prefix before impact':>21}  status")
    for r in rows:
        stages = r["stages_covered"].split(";")
        c = per_window_bits(r)
        # single stage: the cheapest covered stage
        h1 = min(H_STAGE[s] for s in stages)
        t1 = None if c is None else (math.inf if c == 0 else max(0.0, h1 - 1) / c * T_W)
        covered_all = all(s in stages for s in PREFIX)
        tp = "never (coverage)" if not covered_all else (
            "unresolved" if c is None else fmt(max(0.0, sum(H_STAGE[s] for s in PREFIX) - 1) / c * T_W))
        cs = "?" if c is None else f"{c:.4f}"
        print(f"{r['system']:<12} {r['stages_covered']:<8} {cs:>13} {fmt(t1):>19} {tp:>21}  {r['status']}")


if __name__ == "__main__":
    main()
