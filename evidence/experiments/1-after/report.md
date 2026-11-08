# Step 1, after side: Does a council beat one agent?

Run `1-after`, finished 2026-11-08T12:15:22+00:00 (UTC).

## What changed

The reviewer: one agent, then the Analyst / Skeptic / Chair council. The evidence and settings stay at the base profile.

This side ran the `base` profile with council review:

| Setting | Value |
| --- | --- |
| Source window, lines either side | 25 |
| Related source (other files, called methods, referenced scripts) | off |
| Reasoning worksheet (analysis field) and consistency repair | off |
| Guidance retrieval | map |

On in every profile: strict JSON schema output; guidance-label normalisation in the validator; LangGraph council (Analyst || Skeptic -> Chair); output token limit with room for hidden reasoning (2000).

## Results

Case set `comparison` (all 96 cases), SHA-256 `311c5e73b3e9`. Precision, recall and F1 count a case sent to a human as kept.

| Measure | C council (raw) | D council (validated) |
| --- | ---: | ---: |
| Precision | 73.0% | 73.0% |
| Recall | 95.8% | 95.8% |
| F1 | 82.9% | 82.9% |
| Real vulnerabilities dismissed | 2 of 48 | 2 of 48 |
| False alarms removed | 31 of 48 | 31 of 48 |
| Sent to a human | 31 of 96 | 31 of 96 |
| Invalid answers | 0 | 0 |
| Mean latency (s) | 20.19 | 20.19 |
| Total cost (US$) | 1.0659 | 1.0659 |
| Prompt tokens | 789,929 | 789,929 |

Model `google/gemini-3.8-flash`, temperature 0.0. 288 model calls, 0 failed; total cost US$1.0659; 789,929 prompt tokens.
Code: commit `d2c214dda85b`.

## Reproduce

- Show the before/after table (free, offline): `python -m triagebot experiment show 1`
- Re-score the saved outputs (free, needs the Benchmark answer key): `python -m triagebot experiment replay 1`
- Re-run (paid, asks first): delete this folder, then `python -m triagebot experiment run 1 --side after`
