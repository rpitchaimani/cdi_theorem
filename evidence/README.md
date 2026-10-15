# Proof-of-concept evidence

Logs from the three-stage hardware run (initial access, execution, lateral
movement) on the NXP MPC5748G bench. The impact stage was not run.

| File | Stage | What it shows |
|---|---|---|
| `tIA_results.json` | Initial access | Host scan and ARP sweep: hosts found and the chosen target. |
| `tEX_results.json` | Execution | 50 fragment-flood bursts; per-burst round-trip times and the payload entropy. |
| `TEX_UART.png` | Execution | IDS UART output: per-window alerts raised while capacity was positive. |
| `tLM_results.json` | Lateral movement | Send timestamp and the recorded blindness of the IDS once the mirrored-port input went silent. Exploit parameters withheld. |
| `TAU_LM_UART.png` | Lateral movement | IDS UART output: the monitor flags silence once its input stops. |

Per-window capacity in bits is computed by `python/cdi_compute.py`, not
stored in these files. No capacity value in this directory is a stored
constant.
