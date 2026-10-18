# AI Use Log: Lisa

Entries follow the SE201 AI Use Disclosure Policy v1.00: one entry per
significant use, committed with the work it describes.

## 2026-10-17 — Deterministic validation gate and offline tests

- **Tool (model):** Claude Code (Sonnet 5.5)
- **Files:** triagebot/nodes/validate/validator.py, tests/test_validator.py,
  README.md (files table and test command)
- **Outcome:** Changed

### What I asked for

The deterministic validator described in `CHECKPOINT_LISA.md`: check the result
structure, the three allowed verdicts, a non-empty explanation, and every
citation (expected file, existing line, non-empty exact quote); require exactly
one result per requested case ID and reject duplicate or unknown IDs; fall back
to `human_review` with reasons and never to `false_positive`; return a compact
record the evaluator can score. It had to work offline, for single-agent and
council output alike, without touching other members' files.

### How I checked it

Ran the 32 offline tests written with it, covering a valid citation, a
fabricated quote, a wrong file, an out-of-range line, malformed JSON, a missing
case, a duplicate case, an unsupported verdict, and a deliberately fabricated
"sanitizeSQL" claim that must be rejected. Ran the existing
`verification/openrouter_smoke.py --self-test`, and a parity test confirming the
new body checks agree with that script's older `validate`. Confirmed the
validator reads no files, makes no network calls and never sees the answer key.
After merge, the validator tests number 41 because Darren extended the file.

### What I kept or changed

Kept the checks as designed and the `human_review` fallback with
`original_verdict` preserved so invalid output stays measurable. Moved the work
from `verification/` to `triagebot/nodes/validate/` after the repository was
restructured, and left `verification/openrouter_smoke.py` unedited so the
feasibility record stays unchanged.

### Disclosure note

Commit `e7cea32` ("validation: reject unsupported triage evidence") contains
this AI-assisted work but was committed without the `Assisted-by:` trailer
required by decision 16. It was already merged (PR #2), so history was not
rewritten; this entry is the disclosure, and later commits carry the trailer.
