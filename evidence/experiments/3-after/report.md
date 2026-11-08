# Step 3, after side: Does a reasoning worksheet with a consistency check help?

Run `3-after`, finished 2026-11-08T12:34:43+00:00 (UTC).

## What changed

The output: a structured analysis (source, sink, reaches the sink, protection, protection effective) is required, and a verdict that contradicts it gets one repair call.

This side ran the `worksheet` profile with council review:

| Setting | Value |
| --- | --- |
| Source window, lines either side | 60 |
| Related source (other files, called methods, referenced scripts) | on |
| Reasoning worksheet (analysis field) and consistency repair | on |
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
| Sent to a human | 3 of 96 | 3 of 96 |
| Invalid answers | 0 | 0 |
| Mean latency (s) | 21.44 | 21.44 |
| Total cost (US$) | 1.4837 | 1.4837 |
| Prompt tokens | 1,201,205 | 1,201,205 |

Model `google/gemini-3.8-flash`, temperature 0.0. 288 model calls, 1 failed; total cost US$1.4837; 1,201,205 prompt tokens.
Code: commit `d2c214dda85b`.

## Reproduce

- Show the before/after table (free, offline): `python -m triagebot experiment show 3`
- Re-score the saved outputs (free, needs the Benchmark answer key): `python -m triagebot experiment replay 3`
- Re-run (paid, asks first): delete this folder, then `python -m triagebot experiment run 3 --side after`
