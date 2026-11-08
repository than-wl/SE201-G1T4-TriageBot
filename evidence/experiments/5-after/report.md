# Step 5, after side: Does the verdict follow the code?

Run `5-after`, finished 2026-11-08T20:50:31+00:00 (UTC).

## What changed

The code: in each case one constant condition is flipped ('num > 200' to 'num < 200', the same length, so no line moves), which flips which branch runs and so the right verdict. Before: the originals; after: their mutants, each read from its own overlay root (the Benchmark source with only the mutated file replaced), so both are judged on the same evidence except that line. Both sides run the final version (the semantic profile), single agent and council, on one commit.

This side ran the `semantic` profile with single and council review:

| Setting | Value |
| --- | --- |
| Source window, lines either side | 60 |
| Related source (other files, called methods, referenced scripts) | on |
| Reasoning worksheet (analysis field) and consistency repair | off |
| Guidance retrieval | semantic |

On in every profile: strict JSON schema output; guidance-label normalisation in the validator; LangGraph council (Analyst || Skeptic -> Chair); output token limit with room for hidden reasoning (2000).

## Results

Case set `mutation` (all 22 cases), SHA-256 `bbaee0f17903`. Precision, recall and F1 count a case sent to a human as kept.

Code: each mutant was read from its own overlay root (the Benchmark source with only the mutated file replaced) and scored against the flipped answers; the mutation score is in the after side's mutation_score.json.

| Measure | B single agent | C council (raw) | D council (validated) |
| --- | ---: | ---: | ---: |
| Precision | 100.0% | 100.0% | 100.0% |
| Recall | 45.5% | 100.0% | 100.0% |
| F1 | 62.5% | 100.0% | 100.0% |
| Real vulnerabilities dismissed | 6 of 11 | 0 of 11 | 0 of 11 |
| False alarms removed | 11 of 11 | 11 of 11 | 11 of 11 |
| Sent to a human | 1 of 22 | 0 of 22 | 0 of 22 |
| Invalid answers | 0 | 0 | 0 |
| Mean latency (s) | 11.02 | 19.70 | 19.70 |
| Total cost (US$) | 0.1016 | 0.3126 | 0.3126 |
| Prompt tokens | 70,450 | 249,395 | 249,395 |

Model `google/gemini-3.8-flash`, temperature 0.0. 88 model calls, 2 failed; total cost US$0.4142; 319,845 prompt tokens.
Code: commit `e54eef660347`.

## Reproduce

- Show the before/after table (free, offline): `python -m triagebot experiment show 5`
- Re-score the saved outputs (free, needs the Benchmark answer key): `python -m triagebot experiment replay 5`
- Re-run (paid, asks first): delete this folder, then `python -m triagebot experiment run 5 --side after`
