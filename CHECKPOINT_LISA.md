# Lisa — Deterministic Validation and Human Review

## Your part in simple terms

You build the safety gate after the AI responds.

The AI may return malformed JSON, cite the wrong file, invent a quote, or make a claim that cannot be checked. Your validator checks the response mechanically. If the response is unsafe or incomplete, it becomes `human_review` instead of being trusted automatically.

Your work protects the whole project from treating an unsupported AI answer as a correct security decision.

```text
AI result -> deterministic checks -> accepted result or human review
```

## What you own

Suggested files:

- `verification/validator.py`
- `verification/tests/test_validator.py`

Reuse and extend the existing validation logic in `verification/openrouter_smoke.py` so the repository has one compatible validation rule set.

Do not call OpenRouter and do not use the OWASP answer key to decide whether a model response is structurally valid. Ground-truth scoring belongs to Bradley.

## What you need to produce

1. A validator for both single-agent and council outputs.
2. A safe fallback to `human_review` for malformed, missing, unsupported, or unverifiable results.
3. Exact citation checks against the expected source file and source lines.
4. Duplicate, missing, and unknown case-ID checks.
5. A compact validated result that Bradley can score.
6. Tests demonstrating both accepted and rejected responses.

## How to do it

1. Read `README.md` and the shared result schema in `CHECKPOINT_TEAM_TASKS.md`.
2. Validate the top-level result structure.
3. Accept only `true_positive`, `false_positive`, and `human_review` verdicts.
4. Require a non-empty explanation and at least one citation.
5. For every citation, check that:
   - the file is the expected source file;
   - the line number exists;
   - the quote is an exact substring of that source line;
   - the quote is non-empty.
6. Require exactly one result for each requested case ID.
7. Reject duplicate or unknown case IDs.
8. Add only small identifier checks that can be verified mechanically. Do not attempt whole-program semantic analysis for this checkpoint.
9. On failure, return `human_review` with explicit validation reasons.
10. Never silently convert an invalid response to `false_positive`.
11. Keep the validator independent of the selected model or agent role.

## Your offline test

Include tests for:

- a valid source citation;
- a fabricated quote;
- a wrong file;
- an out-of-range line;
- malformed JSON;
- a missing case;
- a duplicate case;
- an unsupported verdict.

At least one deliberately fabricated AI claim must be rejected. This becomes useful checkpoint evidence that the safety gate actually works.

## Do you need to wait?

No. You can start immediately with hand-written source lines and result fixtures.

You do not need Hong Yi's finished council implementation: validate the shared result shape first. Later, plug in real single-agent and council outputs. Bradley will need your final validated-output shape before the evaluation harness is integrated, but you can develop independently now.

## OpenRouter key

You do not need an OpenRouter key. Your work is deterministic and must run offline.

Repository access does not provide access to the project owner's OpenRouter key. Do not request, copy, or commit the owner's key. If a live result is needed for a test, Hong Yi or the project owner can provide a sanitised saved response; your validator should not depend on network access.

## Definition of done

- [ ] The validator runs without OpenRouter.
- [ ] Valid evidence passes.
- [ ] Invalid evidence fails safely to `human_review` with reasons.
- [ ] Single-agent and council results use the same validator.
- [ ] Tests cover successful and rejected outputs.
- [ ] The validator does not read or expose the answer key.
- [ ] No credential or raw model response is committed.
- [ ] You make at least one meaningful commit under your own Git identity.

## Git workflow

```powershell
git switch -c checkpoint/lisa-validation
# implement and test your component
git add verification
git commit -m "validation: reject unsupported triage evidence"
git push -u origin checkpoint/lisa-validation
```

Ask for review or open a pull request after the offline test passes.

