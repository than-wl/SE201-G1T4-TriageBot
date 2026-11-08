# Frozen case sets

These files fix *which* OWASP Benchmark cases each experiment is measured on.
They are built once, committed, and never edited by hand. The experiments that
use them are described in [EXPERIMENTS.md](../../EXPERIMENTS.md).

## Why we split the cases at all

TriageBot trains no model, but we tune it: we read the cases it gets wrong
and change prompts, evidence and settings. A change made after reading a
case tends to fix *that* case. Measured on the same cases, the change then
looks better than it really is. So the cases we read and tune on are kept
apart from the cases we report.

## The sets

| Set | Half of the split | Cases | Composition | What it is for |
| --- | --- | ---: | --- | --- |
| `pilot` | development | 100 | SQL injection (CWE-89): 50 real, 50 safe | The start of the **exploration set**. It is exactly the checkpoint sample (`evidence/checkpoint-100/`). |
| `comparison` | development | 96 | CWE-22, CWE-78, CWE-79, CWE-89: 24 each (12 real, 12 safe) | The **comparison set**. Frozen. Steps 1 to 4 are measured on it, and nobody tunes on it. |
| `final-test` | test | 120 | CWE-22, CWE-78, CWE-79, CWE-89: 30 each (15 real, 15 safe) | The **final test**. Run once, after the code freeze (step 6). |
| `retired_cases.json` | both | 407 | Case IDs only | **Retired** cases: used by earlier runs, kept only as a record. |
| mutation set | — | — | — | **Planned.** A rebuilt mutation test (step 5) will be added in a later task. |

- **Exploration set:** the pilot plus any other development case that is in no
  frozen set. This is where we read failures and try ideas.
- **Comparison set:** only measured. If a failure here suggests an idea, the
  idea is tried on exploration cases first.
- **Final test:** run once. It shares no case with the retired list (the
  builder checks this and stops if it ever does).
- **Retired cases:** every case in a `selected_alerts.json` under `evidence/`,
  plus the 287-case audit list in `evidence/fresh-120/prior_case_audit.json`
  (which adds the one OpenRouter smoke-test case). They are never used for a
  new claim.

## Files

Each set has two files:

- `<set>.json`: the alerts the model sees, in the same shape as
  `selected_alerts.json`. Each alert has only the scanner's fields (case ID,
  file, rule, CWE, lines, message). There are **no labels**: the answer key
  never reaches a model-side file (design decision 7). Tests check this.
- `<set>.manifest.json`: how the set was built: the rule, the seed (201), the
  test fraction (0.5), the scan file and its SHA-256, the answer key's SHA-256,
  the sample file's own SHA-256, the case count, and the count of real and
  safe cases per CWE. These totals are evaluation-side; there is no per-case
  label.

Fingerprints are SHA-256 hashes of the file **with LF line endings**, so they
are the same on Windows and macOS even if Git checks a file out with CRLF.
`.gitattributes` keeps these files LF on checkout as well.

| Set | SHA-256 |
| --- | --- |
| `pilot` | `2b633145f724df28b6fffb112bbcce8304fbfa73d14aaa4100f4c8e7bebc578d` |
| `comparison` | `311c5e73b3e909af005711a03a1aa04be69b060a13fe1923dc16dee615d7e91a` |
| `final-test` | `3182ce45723df68a6932c2dfbf747811cf60a5fee3170c172a1222b575f7c543` |

## How they are built

```bash
python -m triagebot.nodes.ingest.eval_sets build
```

The builder needs the OWASP Benchmark answer key (it balances the draw) and
reads the recorded Semgrep scan `data/semgrep/semgrep-owasp-p-java-1.178.0.json`.
It uses the fixed development/test split (seed 201, half of each category and
label in each part, design decision 18) and picks **one CWE-matching Semgrep
alert per case**: the alert with the lowest start line, then rule ID. Cases
are drawn with seed 201, half real and half safe. It makes no model calls.

The builder stops with an error, and writes nothing, if:

- the pilot differs from `evidence/checkpoint-100/selected_alerts.json`;
- a category has too few eligible cases;
- the final test, or the comparison set, would contain a retired case.

Running it twice gives byte-identical files. Rebuilding should never be needed;
if the scan, the answer key or the split ever changed, the fingerprints would
change too, and every earlier result would stop being comparable.
