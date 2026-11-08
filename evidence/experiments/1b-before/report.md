# Step 1b, before side: Does the council beat one agent once the AI sees more of the code?

Run `1b-before`, finished 2026-11-08T12:58:48+00:00 (UTC).

## What changed

The reviewer, as in step 1, but at the evidence profile (60 lines either side plus related source). Step 1 compared them at the base profile; this tests whether the council's value depends on the evidence it gets.

This side ran the `evidence` profile with single review:

| Setting | Value |
| --- | --- |
| Source window, lines either side | 60 |
| Related source (other files, called methods, referenced scripts) | on |
| Reasoning worksheet (analysis field) and consistency repair | off |
| Guidance retrieval | map |

On in every profile: strict JSON schema output; guidance-label normalisation in the validator; LangGraph council (Analyst || Skeptic -> Chair); output token limit with room for hidden reasoning (2000).

## Results

Case set `comparison` (all 96 cases), SHA-256 `311c5e73b3e9`. Precision, recall and F1 count a case sent to a human as kept.

| Measure | B single agent |
| --- | ---: |
| Precision | 93.8% |
| Recall | 93.8% |
| F1 | 93.8% |
| Real vulnerabilities dismissed | 3 of 48 |
| False alarms removed | 45 of 48 |
| Sent to a human | 4 of 96 |
| Invalid answers | 0 |
| Mean latency (s) | 11.06 |
| Total cost (US$) | 0.4146 |
| Prompt tokens | 329,461 |

Model `google/gemini-3.8-flash`, temperature 0.0. 96 model calls, 1 failed; total cost US$0.4146; 329,461 prompt tokens.
Code: commit `806f0b794a16`.

## Reproduce

- Show the before/after table (free, offline): `python -m triagebot experiment show 1b`
- Re-score the saved outputs (free, needs the Benchmark answer key): `python -m triagebot experiment replay 1b`
- Re-run (paid, asks first): delete this folder, then `python -m triagebot experiment run 1b --side before`
