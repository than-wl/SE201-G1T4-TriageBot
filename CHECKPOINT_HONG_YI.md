# Hong Yi — Single-Agent and Multi-Agent Orchestration

## Your part in simple terms

You build the part that asks the AI to review a Semgrep finding.

The input is a common evidence package containing the alert, relevant source code, helper evidence, and security guidance. You must support two comparable modes:

```text
common evidence -> one AI reviewer
common evidence -> Analyst -> Skeptic -> Chair
```

Your work demonstrates the chosen AI technique and lets Bradley compare whether the multi-agent council is more useful than a simpler single-agent review.

## What you own

Suggested files:

- `verification/council.py`
- `verification/tests/test_council.py`
- small sanitised request/response fixtures under `verification/fixtures/`

Refactor from the existing request and schema logic in `verification/feasibility_checks.py` where useful. Do not rewrite working code without a reason.

Do not own answer-key scoring or deterministic citation validation. Darren owns mapping; Lisa owns the safety validator; Bradley owns evaluation.

## What you need to produce

1. An offline-capable single-agent path.
2. An offline-capable Analyst/Skeptic/Chair path.
3. A live OpenRouter caller that can be swapped for a fixture/replay caller.
4. Model, token usage, latency, and approximate cost recorded in results.
5. A model setting controlled through `OPENROUTER_MODEL`, rather than hardcoded in source.
6. A small test proving that answer-key fields never enter prompts.

The triage result should follow the shared shape:

```json
{
  "case_id": "BenchmarkTest00008",
  "verdict": "true_positive",
  "explanation": "Short evidence-based explanation",
  "citations": [
    {
      "file": "path/to/BenchmarkTest00008.java",
      "line": 42,
      "quote": "exact text from the cited line"
    }
  ]
}
```

Allowed verdicts are `true_positive`, `false_positive`, and `human_review`.

## How to do it

1. Read `README.md`, `Context/README.md`, and the shared interfaces in `CHECKPOINT_TEAM_TASKS.md`.
2. Separate the OpenRouter request function from the orchestration logic.
3. Make the caller injectable so the same workflow can use live calls or fixed offline responses.
4. Read the model from `OPENROUTER_MODEL`; default development calls to `google/gemini-3.5-flash-lite`.
5. Read `OPENROUTER_API_KEY` only from the local `.env` file. Never commit `.env`.
6. Use exactly the same common evidence when comparing the single-agent and council modes.
7. Implement the roles:
   - Analyst: trace input toward the dangerous operation and identify supporting evidence.
   - Skeptic: look for constants, sanitisation, guards, overwritten values, unreachable paths, and missing context.
   - Chair: compare both reports and return one supported verdict.
8. Make the single-agent baseline receive the union of the evidence available to the two specialists so the comparison is fair.
9. Require structured JSON and exact source citations.
10. Add low token limits, a client-side budget check, and no automatic retry after timeout or billing-uncertain failure.
11. Save live requests and responses only under ignored `Context/tmp/checkpoint/`.
12. Run offline tests before using a temporary key for a small live sample.

## Your offline test

Use fixed Analyst, Skeptic, and Chair fixture responses. Prove that:

- every input case receives one result;
- the Chair receives both specialist reports;
- invalid JSON becomes an explicit error;
- no answer-key field appears in any prompt payload;
- the workflow runs without network access.

## Do you need to wait?

No. Start immediately with a hand-written normalised alert and fixed response fixtures.

For final integration, you will need Darren's normalised alert format and selected cases, but you can build the orchestration boundary before Darren finishes. Lisa can also test against your output later, so keep the result schema stable.

## OpenRouter key

You are the only member whose assigned component may need a live development key. Even you do not need one to complete the offline implementation and tests.

The project owner should either run the small live test personally or create a separate temporary key for you with a very small spending limit and expiry. Do not share the owner's personal key, place it in `.env` committed to Git, or paste it into GitHub issues or pull requests. Repository membership does not grant OpenRouter access.

The owner should run the final paid comparison with the proposal model, `google/gemini-3.8-flash`, after the pipeline is integrated. Record the exact model used.

## Definition of done

- [ ] One command runs the single-agent path.
- [ ] One command runs the Analyst/Skeptic/Chair path.
- [ ] Both paths work offline with fixtures.
- [ ] Model selection can change through `OPENROUTER_MODEL`.
- [ ] Model, token usage, latency, and approximate cost are captured.
- [ ] A small live run works if a temporary key is provided.
- [ ] The final model can be selected without editing source code.
- [ ] No answer key, credential, or raw live response is committed.
- [ ] You make at least one meaningful commit under your own Git identity.

## Git workflow

```powershell
git switch -c checkpoint/hong-yi-council
# implement and test your component
git add verification
git commit -m "council: add replayable single and multi-agent workflows"
git push -u origin checkpoint/hong-yi-council
```

Ask for review or open a pull request after the offline test passes.

