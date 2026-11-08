# Step 1c, before side: Does the council beat one agent once the AI also fills in the reasoning worksheet?

Run `1c-before`, finished 2026-11-08T12:59:23+00:00 (UTC).

## What changed

The reviewer, as in step 1, but at the worksheet profile (more code plus the reasoning worksheet and consistency repair).

This side ran the `worksheet` profile with single review:

| Setting | Value |
| --- | --- |
| Source window, lines either side | 60 |
| Related source (other files, called methods, referenced scripts) | on |
| Reasoning worksheet (analysis field) and consistency repair | on |
| Guidance retrieval | map |

On in every profile: strict JSON schema output; guidance-label normalisation in the validator; LangGraph council (Analyst || Skeptic -> Chair); output token limit with room for hidden reasoning (2000).

## Results

Case set `comparison` (all 96 cases), SHA-256 `311c5e73b3e9`. Precision, recall and F1 count a case sent to a human as kept.

| Measure | B single agent |
| --- | ---: |
| Precision | 93.5% |
| Recall | 89.6% |
| F1 | 91.5% |
| Real vulnerabilities dismissed | 5 of 48 |
| False alarms removed | 45 of 48 |
| Sent to a human | 3 of 96 |
| Invalid answers | 0 |
| Mean latency (s) | 11.39 |
| Total cost (US$) | 0.4700 |
| Prompt tokens | 346,232 |

Model `google/gemini-3.8-flash`, temperature 0.0. 96 model calls, 0 failed; total cost US$0.4700; 346,232 prompt tokens.
Code: commit `806f0b794a16`.

## Reproduce

- Show the before/after table (free, offline): `python -m triagebot experiment show 1c`
- Re-score the saved outputs (free, needs the Benchmark answer key): `python -m triagebot experiment replay 1c`
- Re-run (paid, asks first): delete this folder, then `python -m triagebot experiment run 1c --side before`
