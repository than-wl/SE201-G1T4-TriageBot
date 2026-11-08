# Step 1, before side: Does a council beat one agent?

Run `1-before`, finished 2026-11-08T11:33:02+00:00 (UTC).

## What changed

The reviewer: one agent, then the Analyst / Skeptic / Chair council. The evidence and settings stay at the base profile.

This side ran the `base` profile with single review:

| Setting | Value |
| --- | --- |
| Source window, lines either side | 25 |
| Related source (other files, called methods, referenced scripts) | off |
| Reasoning worksheet (analysis field) and consistency repair | off |
| Guidance retrieval | map |

On in every profile: strict JSON schema output; guidance-label normalisation in the validator; LangGraph council (Analyst || Skeptic -> Chair); output token limit with room for hidden reasoning (2000).

## Results

Case set `comparison` (all 96 cases), SHA-256 `311c5e73b3e9`. Precision, recall and F1 count a case sent to a human as kept.

| Measure | B single agent |
| --- | ---: |
| Precision | 71.4% |
| Recall | 93.8% |
| F1 | 81.1% |
| Real vulnerabilities dismissed | 3 of 48 |
| False alarms removed | 30 of 48 |
| Sent to a human | 32 of 96 |
| Invalid answers | 0 |
| Mean latency (s) | 10.98 |
| Total cost (US$) | 0.3495 |
| Prompt tokens | 217,213 |

Model `google/gemini-3.8-flash`, temperature 0.0. 96 model calls, 1 failed; total cost US$0.3495; 217,213 prompt tokens.
Code: commit `d2c214dda85b`.

## Reproduce

- Show the before/after table (free, offline): `python -m triagebot experiment show 1`
- Re-score the saved outputs (free, needs the Benchmark answer key): `python -m triagebot experiment replay 1`
- Re-run (paid, asks first): delete this folder, then `python -m triagebot experiment run 1 --side before`
