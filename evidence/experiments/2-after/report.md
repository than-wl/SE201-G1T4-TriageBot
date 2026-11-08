# Step 2, after side: Does showing the AI more of the code help?

Run `2-after`, finished 2026-11-08T12:33:42+00:00 (UTC).

## What changed

The evidence: source window 25 to 60 lines either side, and related source (called methods, other files, referenced scripts) switched on.

This side ran the `evidence` profile with council review:

| Setting | Value |
| --- | --- |
| Source window, lines either side | 60 |
| Related source (other files, called methods, referenced scripts) | on |
| Reasoning worksheet (analysis field) and consistency repair | off |
| Guidance retrieval | map |

On in every profile: strict JSON schema output; guidance-label normalisation in the validator; LangGraph council (Analyst || Skeptic -> Chair); output token limit with room for hidden reasoning (2000).

## Results

Case set `comparison` (all 96 cases), SHA-256 `311c5e73b3e9`. Precision, recall and F1 count a case sent to a human as kept.

| Measure | C council (raw) | D council (validated) |
| --- | ---: | ---: |
| Precision | 92.3% | 92.3% |
| Recall | 100.0% | 100.0% |
| F1 | 96.0% | 96.0% |
| Real vulnerabilities dismissed | 0 of 48 | 0 of 48 |
| False alarms removed | 44 of 48 | 44 of 48 |
| Sent to a human | 4 of 96 | 4 of 96 |
| Invalid answers | 0 | 1 |
| Mean latency (s) | 20.91 | 20.91 |
| Total cost (US$) | 1.3701 | 1.3701 |
| Prompt tokens | 1,135,897 | 1,135,897 |

Model `google/gemini-3.8-flash`, temperature 0.0. 288 model calls, 1 failed; total cost US$1.3701; 1,135,897 prompt tokens.
Code: commit `d2c214dda85b`.

## Reproduce

- Show the before/after table (free, offline): `python -m triagebot experiment show 2`
- Re-score the saved outputs (free, needs the Benchmark answer key): `python -m triagebot experiment replay 2`
- Re-run (paid, asks first): delete this folder, then `python -m triagebot experiment run 2 --side after`
