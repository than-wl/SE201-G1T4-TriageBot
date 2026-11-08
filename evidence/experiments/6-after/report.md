# Step 6, after side: How well does the final system do on cases it has never seen?

Run `6-after`, finished 2026-11-08T20:16:29+00:00 (UTC).

## What changed

Nothing is changed: the final version (the semantic profile, design decision 29), single agent and council, run once on the unseen final test after the code freeze.

This side ran the `semantic` profile with council review:

| Setting | Value |
| --- | --- |
| Source window, lines either side | 60 |
| Related source (other files, called methods, referenced scripts) | on |
| Reasoning worksheet (analysis field) and consistency repair | off |
| Guidance retrieval | semantic |

On in every profile: strict JSON schema output; guidance-label normalisation in the validator; LangGraph council (Analyst || Skeptic -> Chair); output token limit with room for hidden reasoning (2000).

## Results

Case set `final-test` (all 120 cases), SHA-256 `3182ce45723d`. Precision, recall and F1 count a case sent to a human as kept.

| Measure | C council (raw) | D council (validated) |
| --- | ---: | ---: |
| Precision | 95.2% | 95.2% |
| Recall | 98.3% | 98.3% |
| F1 | 96.7% | 96.7% |
| Real vulnerabilities dismissed | 1 of 60 | 1 of 60 |
| False alarms removed | 57 of 60 | 57 of 60 |
| Sent to a human | 1 of 120 | 1 of 120 |
| Invalid answers | 0 | 0 |
| Mean latency (s) | 18.77 | 18.77 |
| Total cost (US$) | 1.7599 | 1.7599 |
| Prompt tokens | 1,411,092 | 1,411,092 |

Model `google/gemini-3.8-flash`, temperature 0.0. 360 model calls, 2 failed; total cost US$1.7599; 1,411,092 prompt tokens.
Code: commit `e39e415994a6`.

## Reproduce

- Show the before/after table (free, offline): `python -m triagebot experiment show 6`
- Re-score the saved outputs (free, needs the Benchmark answer key): `python -m triagebot experiment replay 6`
- Re-run (paid, asks first; the final test is run once, so only on purpose): `python -m triagebot experiment run 6 --side after --i-know-this-reruns-the-final-test`, which moves this folder to `6-after-superseded-<time>/`
