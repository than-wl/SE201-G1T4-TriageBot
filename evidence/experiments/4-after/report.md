# Step 4, after side: Does semantic retrieval hold up?

Run `4-after`, finished 2026-11-08T17:18:22+00:00 (UTC).

## What changed

The guidance ranker: the curated CWE map, then semantic search with the official MITRE text of the alert's CWE. Built on step 2 (evidence profile, council); the worksheet from step 3 showed no benefit and is not carried forward.

This side ran the `semantic` profile with council review:

| Setting | Value |
| --- | --- |
| Source window, lines either side | 60 |
| Related source (other files, called methods, referenced scripts) | on |
| Reasoning worksheet (analysis field) and consistency repair | off |
| Guidance retrieval | semantic |

On in every profile: strict JSON schema output; guidance-label normalisation in the validator; LangGraph council (Analyst || Skeptic -> Chair); output token limit with room for hidden reasoning (2000).

## Results

Case set `comparison` (all 96 cases), SHA-256 `311c5e73b3e9`. Precision, recall and F1 count a case sent to a human as kept.

| Measure | C council (raw) | D council (validated) |
| --- | ---: | ---: |
| Precision | 92.2% | 92.2% |
| Recall | 97.9% | 97.9% |
| F1 | 95.0% | 95.0% |
| Real vulnerabilities dismissed | 1 of 48 | 1 of 48 |
| False alarms removed | 44 of 48 | 44 of 48 |
| Sent to a human | 4 of 96 | 4 of 96 |
| Invalid answers | 0 | 1 |
| Mean latency (s) | 21.90 | 21.90 |
| Total cost (US$) | 1.3955 | 1.3955 |
| Prompt tokens | 1,113,575 | 1,113,575 |

Model `google/gemini-3.8-flash`, temperature 0.0. 288 model calls, 4 failed; total cost US$1.3955; 1,113,575 prompt tokens.
Code: commit `2c7d9ec28929`.

## Reproduce

- Show the before/after table (free, offline): `python -m triagebot experiment show 4`
- Re-score the saved outputs (free, needs the Benchmark answer key): `python -m triagebot experiment replay 4`
- Re-run (paid, asks first): delete this folder, then `python -m triagebot experiment run 4 --side after`
