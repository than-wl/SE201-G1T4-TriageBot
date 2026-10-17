# Recorded Semgrep scan

`semgrep-owasp-p-java-1.178.0.json` is the Semgrep scan of the OWASP Benchmark that TriageBot scores by default. It is committed so that a first run needs no Semgrep install or scan, and so that everyone on the team scores exactly the same scan (the `p/java` ruleset is fetched from the Semgrep registry at run time and can change between runs).

| Field | Value |
| --- | --- |
| Tool | Semgrep 1.178.0 (`semgrep scan --json`) |
| Ruleset | `p/java` (Semgrep registry) |
| Target | `src/main/java` of OWASP Benchmark Java v1.2 |
| Benchmark commit | `8b67a88d73b2594570fc21150705283de884620b` |
| Scan date | 2026-10-17 20:11 UTC (18 Oct 2026, 04:11 UTC+8) |
| Findings | 1,909 results, 0 errors (325 fixpoint timeouts) |
| Size | about 3.3 MB |

The scan date is also recorded in `triagebot/config.py` (`RECORDED_SCAN_DATE`), because a file's modification time after `git clone` is the checkout time, not the scan time.

## What it contains

Semgrep's own JSON output, unchanged except for paths. The scan was run from the repository root, so every path started with `Context\tmp\BenchmarkJava\` (a later re-scan run from an absolute path also held the machine's user name). `python -m triagebot.nodes.ingest.record_scan` rewrote only those paths to be relative to the benchmark root (`src/main/java/org/owasp/benchmark/...`, forward slashes): `results[].path`, `paths.scanned[]`, `time.fixpoint_timeouts[].location.path`, and the path inside `time.fixpoint_timeouts[].message`. Every other field is as Semgrep wrote it.

It contains **no answer-key data**: nothing from `expectedresults-1.2.csv`, no labels, no split. It is scanner output only, safe for the LLM side of the pipeline.

## Which scan is used

`triagebot/config.py` `effective_scan()`: a local re-scan at `Context/tmp/semgrep-owasp.json` (git-ignored) if it exists, otherwise this recorded scan. The baseline screen's "Scan" line says which one is in use. A re-scan always writes to the local path, never to this file.

## How to reproduce

With `.venv` activated and the benchmark cloned at the pinned commit (README, Quick start):

```bash
pip install -r requirements-scan.txt
python -m triagebot baseline --rescan
```

This writes `Context/tmp/semgrep-owasp.json`; the next runs use it until it is deleted. To replace this recorded file deliberately (for example after a Semgrep upgrade agreed by the team), run the normaliser on the chosen scan and then update the version, date and counts above and `RECORDED_SCAN_DATE`:

```bash
python -m triagebot.nodes.ingest.record_scan --in Context/tmp/semgrep-owasp.json --out data/semgrep/semgrep-owasp-p-java-1.178.0.json
```

## Reproducibility

A fresh scan may not match this file exactly. A later re-scan on the same machine, with the same Semgrep version (1.178.0), ruleset and benchmark commit, produced **1,908** findings: it lacked `tainted-ldapi-from-http-request` on `BenchmarkTest00530.java`, line 94. In that run, Semgrep's taint analysis for that file hit its time limit (a "fixpoint timeout", reported in `time.fixpoint_timeouts`; 291 in that run, 325 in this one), so the rule gave up before reporting. Which files time out varies between runs with machine load, and Semgrep's registry rules can also change over time. This is why the project scores one committed, recorded scan instead of whatever the latest run produced; an independent teammate run matched this file's 1,909 findings.
