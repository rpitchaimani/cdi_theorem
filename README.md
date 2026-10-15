# Too Fast to See — CDI Artifacts

Code and data for the paper *Too Fast to See: Architectural Limits of
Intrusion Detectability in Centralized Automotive Electrical/Electronic
Architectures*.

Cross-Domain Inference (CDI) bounds how much attack information a vehicle
architecture can deliver to any intrusion detection system (IDS) in each
detection window. This repository reproduces the numbers in the paper that
do not depend on withheld offensive code: the attack-narrative entropies,
the per-window capacity and minimum dwell time for the audited systems, and
the evidence from the hardware proof of concept.

## Layout

| Path | Contents |
|---|---|
| `python/hv_atm.py` | Attack-narrative entropies H(V) from the AutoISAC ATM v4.02 technique counts (paper, Section 4). Takes the ATM STIX bundle as an argument (see note below). |
| `python/cdi_compute.py` | The CDI capacity bound, cumulative capacity, and minimum dwell time T_min. |
| `python/audit.py` | Per-window capacity and T_min for the eleven audited IDSs; regenerates the audit table and the T_min values from the worksheet. |
| `python/audit_worksheet.csv` | One row per audited system, every value tied to a passage of the cited source paper. |
| `firmware/core1_ids.c` | Proof-of-concept IDS monitor: per-window entropy estimator and the silence check. |
| `firmware/sja1105_spi.c` | SJA1105Q switch driver. `sja1105_disable_mirror()` is stubbed; see **Withheld**. |
| `evidence/` | Logs from the three-stage hardware run (initial access, execution, lateral movement). See `evidence/README.md`. |

## Reproducing the paper's numbers

```bash
python python/audit.py          # per-system capacity and dwell time
python python/cdi_compute.py    # capacity for the proof-of-concept node
python python/hv_atm.py <atm_bundle.json>   # narrative entropies H(V)
```

`audit.py` and `cdi_compute.py` run with no external data. `hv_atm.py`
reads the **AutoISAC Automotive Threat Matrix (ATM) v4.02 STIX bundle**,
which is distributed by Auto-ISAC and is **not redistributed here**; supply
your own copy as the argument. The entropies follow from the per-tactic
technique counts alone, so any equivalent source of those counts reproduces
them.

## Withheld

Two components that together would form a working exploit chain against a
widely deployed gateway SoC family are withheld: the execution-stage
payload and the lateral-movement register-write sequence (the stubbed
`sja1105_disable_mirror()`). Neither is needed to check any claim in the
paper. See the paper's Ethical Considerations for the release plan.

## Hardware

The proof of concept ran on an NXP MPC5748G zonal gateway with an NXP
SJA1105Q TSN switch, on an isolated laboratory bench. No production vehicle
or live vehicle network was used.

## Citation

> R. Pitchaimani, S. Canard, B. Hammi, and A. S. Spornic. "Too Fast to See:
> Architectural Limits of Intrusion Detectability in Centralized Automotive
> Electrical/Electronic Architectures." 2026.
