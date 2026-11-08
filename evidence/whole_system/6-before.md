# Whole system vs Semgrep alone: run `6-before`, single agent (B)

**projection: final-test rates applied to the full benchmark for the 4 types.**

| | Semgrep alone | Whole system (Semgrep, then TriageBot) |
| --- | ---: | ---: |
| Real vulnerabilities kept | 668 | 568.9 |
| Safe cases kept (false alarms) | 453 | 19.9 |
| Real vulnerabilities missed | 109 | 208.1 |
| Precision | 59.6% | 96.6% |
| Recall | 86.0% | 73.2% |
| F1 | 70.4% | 83.3% |

Recall can only fall: TriageBot never sees what Semgrep missed (FN).

## The formula

For each of the four types, the final-test run gives the share of real vulnerabilities TriageBot keeps (a case sent to a human counts as kept) and the share of safe cases it removes. Those rates are applied to Semgrep's results for that type over the whole benchmark: kept real vulnerabilities are Semgrep's true positives times the keep rate; kept safe cases are Semgrep's false positives times one minus the removal rate; missed real vulnerabilities are Semgrep's false negatives plus Semgrep's true positives times one minus the keep rate. The four types are summed, and precision, recall and F1 are computed from the sums.

## Per type

| CWE | Semgrep TP | Semgrep FP | Semgrep FN | Keep rate (final test) | Removal rate (final test) | Kept real | Kept safe | Missed | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 120 | 106 | 13 | 73.3% (11 of 15) | 93.3% (14 of 15) | 88 | 7.1 | 45.0 | 92.6% | 66.2% |
| CWE-78 | 112 | 96 | 14 | 80.0% (12 of 15) | 86.7% (13 of 15) | 89.6 | 12.8 | 36.4 | 87.5% | 71.1% |
| CWE-79 | 202 | 108 | 44 | 93.3% (14 of 15) | 100.0% (15 of 15) | 188.5 | 0 | 57.5 | 100.0% | 76.6% |
| CWE-89 | 234 | 143 | 38 | 86.7% (13 of 15) | 100.0% (15 of 15) | 202.8 | 0 | 69.2 | 100.0% | 74.6% |

## Caveats

- A projection, not a measurement: TriageBot reviewed the final test's cases only; its rates there are assumed to hold for every alert of the same type.
- Each rate rests on the final test's 15 real and 15 safe cases per type, so one case moves a rate by several points.
- Semgrep is scored per case: a case counts once however many matching alerts it has.

## Provenance

- Scan: `data/semgrep/semgrep-owasp-p-java-1.178.0.json` (SHA-256 `5614cdba5382`); answer key SHA-256 `f0311c850dea` (evaluation side only).
- Run: `6-before` on case set `final-test` (SHA-256 `3182ce45723d`), commit `e39e415994a6`.
- Generated 2026-11-08T20:20:52+00:00 by `python verification/whole_system.py --mode single` at commit `e39e415994a6`.
