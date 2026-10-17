# Darren — Semgrep Integration and OWASP Mapping

## Your part in simple terms

You prepare the input that the rest of TriageBot works on.

Semgrep produces scanner findings, but those findings are not yet in a clean format for the AI workflow. Your job is to turn them into standardised alerts, connect each alert to the correct OWASP Benchmark case, and prepare the scanner-only baseline.

Your work contributes the trusted starting point for the whole pipeline:

```text
Semgrep output -> clean alert format -> OWASP case mapping -> baseline/sample for TriageBot
```

Without this step, Hong Yi cannot run the AI workflow consistently and Bradley cannot measure whether TriageBot improved the scanner results.

## What you own

Suggested files:

- `verification/semgrep_baseline.py`
- `verification/tests/test_semgrep_baseline.py`
- a small sanitised fixture under `verification/fixtures/`

Do not implement the OpenRouter calls, council logic, citation validator, or final report metrics. Those belong to other team members.

## What you need to produce

1. A command that reads Semgrep JSON and produces normalised alerts.
2. A separate mapping from benchmark case ID to the OWASP answer-key label.
3. Scanner-only baseline counts.
4. A deterministic selection of approximately 100 SQL-injection/CWE-89 findings, or a documented smaller sample if time or scanner coverage prevents 100.
5. An offline test proving that mapping errors and duplicates are reported rather than silently discarded.

The downstream alert must not contain the expected answer-key label:

```json
{
  "case_id": "BenchmarkTest00008",
  "file": "path/to/BenchmarkTest00008.java",
  "rule_id": "semgrep-rule-id",
  "cwe": "CWE-89",
  "start_line": 42,
  "end_line": 42,
  "message": "scanner message"
}
```

Keep the answer-key mapping in a separate evaluation-only record. Never place it in an LLM prompt, evidence pack, fixture sent to the model, or saved request payload.

## How to do it

1. Read `README.md` and `Context/README.md`.
2. Use the pinned OWASP Benchmark instructions in `Context/README.md` if the local benchmark is available.
3. Inspect `Context/tmp/semgrep-owasp.json`, or reproduce the Semgrep run if needed.
4. Extract the benchmark case ID from each finding's source path.
5. Normalise each relevant finding into the shared alert structure.
6. Keep answer-key mapping in a separate function or output file used only by evaluation.
7. Decide and document how duplicate findings for one case are handled.
8. Report unmapped paths, CWE/rule mismatches, duplicate findings, and benchmark cases with no finding.
9. Calculate the scanner-only baseline using the answer key:
   - vulnerable case flagged: true positive;
   - safe case flagged: false positive;
   - vulnerable case not flagged: false negative;
   - safe case not flagged: true negative.
10. Select the SQL-injection sample using a repeatable rule. Record the selection rule and random seed if sampling is used.
11. Keep full Semgrep output and generated results under ignored `Context/tmp/checkpoint/`. Commit only sanitised fixtures and aggregate summaries.

## Your offline test

Create a small fixture containing:

- one mapped vulnerable case;
- one mapped safe case;
- two findings for the same case;
- one unmapped source path.

The test should prove that the mapper:

- returns the expected normalised fields;
- applies the documented duplicate policy;
- reports the unmapped path;
- does not add answer-key labels to the downstream alert.

Run the test without an OpenRouter key or network access.

## Do you need to wait?

No. You can start immediately using the existing Semgrep output or a small fixture.

Hong Yi can build against a fixture while you work. Your real selected case list and normalised alerts are needed before the final integrated run, but you do not need to wait for anyone to begin.

## OpenRouter key

You do not need an OpenRouter key for your assigned work. Semgrep parsing, mapping, baseline counts, and tests are offline tasks.

Repository access does not provide access to the project owner's OpenRouter account or key. Never ask a teammate to commit or paste a key into GitHub. If you later need a live model call for debugging, request a separate temporary low-limit key privately; do not use the owner's personal key.

## Definition of done

- [ ] Normalised alerts can be produced by one documented command.
- [ ] The answer-key mapping is separate from the LLM-facing alert/evidence data.
- [ ] Approximately 100 SQL-injection findings are selected, or the shortfall is documented.
- [ ] Duplicates, unmapped cases, and mismatches are counted and visible.
- [ ] Offline tests pass without OpenRouter.
- [ ] No benchmark repository, raw Semgrep output, answer key, or credential is committed.
- [ ] You make at least one meaningful commit under your own Git identity.

## Git workflow

```powershell
git switch -c checkpoint/darren-semgrep
# implement and test your component
git add verification
git commit -m "baseline: map Semgrep findings to OWASP cases"
git push -u origin checkpoint/darren-semgrep
```

Ask for review or open a pull request after the offline test passes.

