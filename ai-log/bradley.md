# AI Use Log: Bradley

## 2026-10-17 | Evaluation harness and its offline tests
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** triagebot/nodes/score/evaluate.py, tests/test_evaluate.py, tests/fixtures/evaluation/, README.md
- **Outcome:** Changed

### What I asked for
An evaluator for my checkpoint task: score saved scanner, single-agent,
council and validated-council results against the OWASP answer key, keep
human review separate from false-positive removal, list failures for the
report, and give the same output every time. Also the five-case offline
test described in my checkpoint brief.

### How I checked it
Worked through the five-case fixture by hand (50% genuine retained, 33.3%
false positives removed, 20% human review) and confirmed the tool prints the
same numbers. Ran the unit tests, which passed. Planted four bugs one at a
time (broken answers counted as removals, human review counted as correct,
duplicates accepted, rates inverted) to see whether the tests notice. Three
were caught; the human-review one was not. Also ran Lisa's validator
(checkpoint/lisa-validation) on sample output and scored its records, and
ran her tests and mine together on her branch. Read through the code with a
section-by-section walkthrough before committing.

### What I kept or changed
Kept the scoring logic. Moved the code from verification/ into
triagebot/nodes/score/ and tests/ after Hong Yi's layout was merged into
main. Added reading of the validator's `validated` field so its records are
scored with their reasons. Added a test for clean human-review cases after
the planted-bug check showed that gap; all four planted bugs are now caught.
