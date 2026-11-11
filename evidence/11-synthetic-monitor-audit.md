# Bounded synthetic monitor experiment — 2026-10-28

## Scope and provenance
Independent offline reproduction of the *original* 40-character, non-overlapping text fingerprint logic in `gate/content-monitor.py`, based on source inspected in the repository. No ZCode instance, real prompts, canary values, live packets or provider API were used. This is a synthetic representation-sensitivity test, not a replication of the Windows network captures.

## Preregistered rule
Prediction: the original detector will match full aligned plaintext windows and miss equivalent offset, short, base64, unicode-escaped and whitespace-reformatted representations. Primary metric: Boolean detection for each of eight fixed cases. Negative control: unrelated payload. Positive controls: exact plaintext in a nominal telemetry payload and in a different non-inference endpoint. Kill condition: any result differs from prediction; stop after eight cases with no tuning.

## Results (executed with corrected fixture on 2026-10-28)
The prior report incorrectly described the initial script as executed: the whitespace-reformatting fixture was not a `(payload, expected)` pair and would raise an unpacking error. That fixture was corrected before the actual container run. The corrected script was run with `python scripts/test-monitor-sensitivity.py` and checked with `python -m py_compile`; **8/8 expectations matched** and the detector produced **two** fingerprints from the synthetic 112-character source. The result is a standalone reproduction of the algorithm, not an independent Windows/network measurement.

| Synthetic payload | Baseline detects? | Interpretation |
|---|---|---|
| Full source text | Yes | Positive control |
| 40-character substring offset by one character | No | Non-overlapping windows create blind spots |
| 24-character excerpt | No | Below 40-character minimum |
| Base64-encoded full source | No | Byte representation changed |
| JSON Unicode escape of full source | No | Encoding dependent |
| Same text with spaces inserted every 10 characters | No | Reformatting dependent |
| Unrelated payload | No | Negative control |
| Full source at different non-inference endpoint | Yes | Matching depends on saved payload, not nominal endpoint |

These are **designed misses**, not evidence of actual ZCode evasion or intentional obfuscation. They falsify the *universal* interpretation of zero matches in the real-work run. They do not overturn the measured absence of those specific fingerprints in those specific collected payloads.

## Code audit / exclusions
- Original monitor extracts model strings only from selected JSON request fields and ignores `metadata` and `tools` keys. Content originating outside those fields or too short may be omitted.
- It searches plain outgoing payload bytes; its live monitor does not apply the decompression/recoding transformations used by the separate collector verifier.
- Its `DIRECT-ATTEMPT` path searches selected application logs, not comprehensive operating-system socket activity.
- Windows firewall rules based on executable locations do not prove isolation for every helper executable the agent can launch.
- The 24-response GLM baseline was not a training test: 16 refusals, no known positive memorization sensitivity; future canary reproduction would require excluding contaminating repositories and retrieval.

## Evidence governance
**M**: observed binary endpoint configuration and bounded local-collector payloads (reported in earlier evidence); **M**: this independently executed synthetic detection test. **H**: content export through inactive trace paths, provider training, retention. **R**: Singapore-exclusive residency, universal absence of leakage, and complete process isolation.

## Next falsifiable measurement
On a disposable VM only, isolate by independent deny-by-default network policy rather than process-path rules. Inject synthetic plaintext and encoded short payloads to a local collector; verify the monitor warns in each specified positive condition and suppresses the unrelated control. Stop at a fixed 10-minute capture or first unanticipated outbound path. Do not use live credentials or private repositories; do not interpret a clean capture as evidence of universal absence.
