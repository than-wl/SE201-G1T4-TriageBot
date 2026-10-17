# TriageBot Checkpoint Team Instructions

## Objective

The checkpoint is due on **18 October 2026 at 23:59 Singapore time**.

We are not trying to finish the final TriageBot product. We need to present one honest, reproducible, measured working slice:

```text
OWASP Benchmark source
        -> Semgrep finding
        -> normalised alert and common evidence
        -> single-agent or Analyst/Skeptic/Chair review
        -> deterministic validation
        -> final verdict
        -> evaluation against the hidden answer key
```

The demonstration category should remain **SQL injection / CWE-89** unless the team jointly decides otherwise. Existing feasibility evidence already covers this category, so changing category now would add unnecessary risk.

## What the checkpoint must contain

The official project brief requires:

1. Read access to a shared repository with setup instructions and commit history showing contributions from every team member.
2. The main architecture components in place and connected. Simplified or stubbed components are allowed if they are documented.
3. At least one core feature from the proposal demonstrated.
4. The chosen AI technique implemented and working in a limited fashion.
5. A checkpoint document containing:
   - results from at least one testing round against the proposed metrics or test cases;
   - failures observed;
   - progress against the proposal's checkpoint targets and any unmet targets;
   - changes to scope, design, or technology and the reasons;
   - the AI-use disclosure log to date.

Our proposal adds these checkpoint targets:

- produce a Semgrep baseline mapped to the OWASP answer key;
- connect the scanner-to-final-output pipeline, documenting stubs;
- demonstrate one reasoning-heavy category end-to-end;
- compare a single agent with the multi-agent council on the same cases;
- evaluate approximately 100 scanner findings and report initial metrics and failures.

## Rules everyone follows

### Keep ground truth separate

The OWASP answer key is used only by Darren's mapping/evaluation preparation and Bradley's scoring code. It must never appear in an LLM prompt, common evidence pack, role report, or saved request payload.

### Keep interfaces small

Each component should exchange ordinary JSON-compatible dictionaries. Do not introduce a web application, database, queue, or agent framework for this checkpoint.

The normalised alert should contain at least:

```json
{
  "case_id": "BenchmarkTest00008",
  "file": "path/to/BenchmarkTest00008.java",
  "rule_id": "semgrep-rule-id",
  "cwe": "CWE-89",
  "start_line": 42,
  "end_line": 42,
  "message": "scanner message"
}
```

The triage result should contain at least:

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

### Keep generated output out of Git

Raw Semgrep output, raw OpenRouter responses, downloaded benchmark files, and temporary outputs belong under `Context/tmp/`, which is ignored. Small sanitised test fixtures and aggregate checkpoint results may be committed when they contain no credentials or restricted material.

### Make individual work visible

Each member should:

1. create a branch named `checkpoint/<name>-<task>`;
2. implement only their assigned component;
3. add a small offline test using Python's standard library;
4. update any command or setup note their component requires;
5. make at least one meaningful commit under their own GitHub identity;
6. open a pull request or ask another member to review before merging.

Wei Lin's two existing commits already show the repository scaffolding contribution. No additional checkpoint task is assigned to Wei Lin unless integration assistance is needed.

## OpenRouter access plan

Repository access does not automatically grant OpenRouter access, and no API key may be committed to Git.

The recommended arrangement is:

1. Only members who need live model calls receive a key. For the current task split, Hong Yi may need a temporary development key; Darren, Lisa, and Bradley can complete their assigned work offline. The account owner may run the final paid batch personally.
2. If a member needs a live call, the account owner creates a separate temporary API key for that member.
3. Give each key a small total spending limit, for example **US$0.25**, and an expiry shortly after the checkpoint.
4. If account guardrails are available, allow only the development model.
5. Send any key privately, never through GitHub, source code, issues, or chat logs that will be committed.
6. The recipient copies `.env.example` to `.env` and adds only their assigned key locally.
7. Revoke all temporary keys after the checkpoint.

Use `google/gemini-3.5-flash-lite` for cheap development calls after Hong Yi makes the model configurable. Use the proposal model, `google/gemini-3.8-flash`, for the recorded final comparison so the final results remain consistent with the proposal and earlier smoke test. Record the exact model used for every run.

Separate keys are preferable to one shared key because they provide individual spend limits and can be revoked independently. If the account owner chooses one shared temporary key instead, it must still have a low hard spending limit and expiry, it should be used only by the person running live calls, and it must never enter the repository.

No member should need paid calls to complete their basic implementation. All components must support offline tests with fixtures or recorded responses.

---

# Darren - Semgrep Integration and Benchmark Mapping

## Responsibility

Own the input side of the pipeline:

```text
Semgrep JSON -> normalised alerts -> benchmark case mapping -> scanner baseline
```

Do not implement LLM calls, council logic, validation, or final metrics presentation.

## Files to own

Suggested files:

- `verification/semgrep_baseline.py`
- `verification/tests/test_semgrep_baseline.py`
- a small sanitised fixture under `verification/fixtures/`

Do not commit the full benchmark repository or the full raw Semgrep JSON.

## Steps

1. Clone the pinned OWASP Benchmark version using `Context/README.md`.
2. Locate `expectedresults-1.2.csv` and inspect its fields.
3. Read the existing Semgrep JSON from `Context/tmp/semgrep-owasp.json`, or reproduce it with Semgrep 1.178.0 and the `p/java` ruleset if necessary.
4. Extract the benchmark case ID from each Semgrep finding's source path.
5. Normalise each relevant Semgrep finding into the shared alert structure above.
6. Map each case ID to the answer-key row only in a separate evaluation record. Do not add the expected label to the normalised alert sent downstream.
7. Handle these cases explicitly:
   - multiple Semgrep findings for one benchmark case;
   - findings that cannot be mapped to a case ID;
   - rule/CWE mismatches;
   - benchmark cases with no Semgrep finding.
8. Produce the scanner-only baseline counts:
   - vulnerable case flagged = true positive;
   - safe case flagged = false positive;
   - vulnerable case not flagged = false negative;
   - safe case not flagged = true negative.
9. Prepare a deterministic sample of approximately 100 SQL-injection scanner findings for the checkpoint. Record the selection rule and random seed if sampling is used.
10. Save full generated results under `Context/tmp/checkpoint/`. Commit only a small fixture and an aggregate summary.

## Offline test

Create a fixture containing:

- one mapped true case;
- one mapped false case;
- two findings for the same case;
- one unmapped path.

The test must prove that mapping, deduplication policy, and unmapped-case reporting work.

## Definition of done

- A documented command produces normalised alerts and the scanner baseline.
- Approximately 100 selected SQL-injection findings are ready for downstream processing.
- The LLM-facing file contains no answer-key labels.
- Mapping failures and duplicates are counted rather than silently discarded.
- A teammate can run the offline test without OpenRouter.

## Commit example

```text
baseline: map Semgrep findings to OWASP cases
```

---

# Hong Yi - Single-Agent and Multi-Agent Orchestration

## Responsibility

Own the AI workflow:

```text
common evidence -> single agent
common evidence -> Analyst -> Skeptic -> Chair
```

Do not own answer-key scoring or deterministic citation validation.

## Files to own

Suggested files:

- `verification/council.py`
- `verification/tests/test_council.py`
- small request/response fixtures under `verification/fixtures/`

Refactor from the existing `verification/feasibility_checks.py` rather than rewriting working request and schema logic from scratch.

## Steps

1. Separate OpenRouter request code from the council orchestration so the workflow can accept either:
   - a live OpenRouter caller; or
   - an offline fixture/replay caller.
2. Read the model slug from `OPENROUTER_MODEL`, with `google/gemini-3.5-flash-lite` as the development default.
3. Keep `OPENROUTER_API_KEY` local in `.env`.
4. Use the same common evidence for every comparison. It should contain the Semgrep alert, sanitised source context, helper evidence, and retrieved OWASP guidance.
5. Implement the three roles:
   - **Analyst:** trace user-controlled input toward the dangerous operation and identify evidence that the finding is genuine.
   - **Skeptic:** look for constants, overwritten values, sanitisation, guards, unreachable paths, and missing context.
   - **Chair:** compare both reports and return one supported verdict.
6. Implement the single-agent baseline using the union of the evidence and helper information available to Analyst and Skeptic. This keeps the comparison fair.
7. Require every role to return structured JSON. Keep explanations short and require exact source citations.
8. Add conservative limits:
   - low `max_tokens` appropriate to the schema;
   - no automatic retry after a timeout or billing-uncertain failure;
   - a per-run client-side budget check;
   - model and usage recorded in the saved result.
9. Save generated requests and responses under `Context/tmp/checkpoint/`, never in tracked fixtures unless they have been reviewed and sanitised.
10. Run offline tests first. Use the temporary OpenRouter key only for a small integration sample before the final batch.

## Offline test

Use fixed fixture responses for Analyst, Skeptic, and Chair. Prove that:

- every input case receives one result;
- the Chair receives both specialist reports;
- invalid JSON is surfaced as an error, not silently accepted;
- no answer-key field is included in any prompt payload;
- the workflow can run without network access.

## Definition of done

- One command runs the single-agent path.
- One command runs the Analyst/Skeptic/Chair path.
- Both work offline with fixtures.
- A small live run works with the development model and a limited key.
- Model, token usage, latency, and cost are captured.
- The final recorded run can switch to `google/gemini-3.8-flash` without editing source code.

## Commit example

```text
council: add replayable single and multi-agent workflows
```

---

# Lisa - Deterministic Validation and Human Review

## Responsibility

Own the safety gate after the AI output:

```text
triage result -> deterministic checks -> accepted result or human review
```

Do not call OpenRouter and do not use the OWASP answer key to decide whether a model response is valid.

## Files to own

Suggested files:

- `verification/validator.py`
- `verification/tests/test_validator.py`

Reuse and extend the existing `validate` logic in `verification/openrouter_smoke.py` rather than maintaining a second incompatible rule set.

## Steps

1. Validate the top-level result structure and allowed verdict.
2. Require a non-empty explanation and at least one citation.
3. For every citation, verify:
   - the cited file is the expected source file;
   - the line number exists;
   - the quote is an exact substring of that source line;
   - the quote is non-empty.
4. Confirm there is exactly one result for every requested case ID and no duplicate or unknown case IDs.
5. Add basic identifier checks where the explanation explicitly names a method or variable and the claim can be checked mechanically. Do not attempt whole-program semantic analysis for the checkpoint.
6. Define the fallback rule:
   - malformed, missing, unsupported, or unverifiable output becomes `human_review`;
   - include the validation reasons;
   - never silently convert an invalid result to `false_positive`.
7. Produce a compact validated result that Bradley's evaluator can consume.
8. Keep the validator independent from any particular model or agent role.

## Offline test

Tests must include:

- a valid source citation;
- a fabricated quote;
- a wrong file;
- an out-of-range line;
- malformed JSON;
- a missing case;
- a duplicate case;
- an unsupported verdict.

At least one deliberately fabricated AI claim must be rejected, because this is explicit evidence for the checkpoint.

## Definition of done

- The validator runs without OpenRouter.
- Valid evidence passes.
- Every malformed or unsupported result fails safely to `human_review` with reasons.
- The same validator handles single-agent and council outputs.
- Tests demonstrate both successful and rejected outputs.

## Commit example

```text
validation: reject unsupported triage evidence
```

---

# Bradley - Evaluation Harness and Checkpoint Report

## Responsibility

Own scoring and the final evidence package:

```text
hidden answer key + scanner/model results -> metrics, failures, checkpoint report
```

Do not modify the prompts or feed the answer key into the AI workflow.

## Files to own

Suggested files:

- `verification/evaluate.py`
- `verification/tests/test_evaluate.py`
- `CHECKPOINT_REPORT.md`
- `AI_USE_DISCLOSURE.md`

## Steps

1. Consume Darren's selected cases and hidden answer-key mapping.
2. Consume the outputs for these configurations:
   - A: Semgrep/scanner-only baseline;
   - B: single LLM agent;
   - C: Analyst/Skeptic/Chair council;
   - D: council plus deterministic validation, if integration time permits.
3. Ensure configurations B and C use the same cases and equivalent evidence access.
4. Calculate at least:
   - number of evaluated scanner findings;
   - genuine scanner findings retained;
   - false-positive alerts removed;
   - genuine vulnerabilities wrongly dismissed;
   - human-review rate;
   - invalid-output rate;
   - latency, token usage, and approximate cost where available.
5. Treat `human_review` separately. Do not count it as a correctly removed false positive.
6. List representative failures, including wrong verdicts, unsupported citations, missing context, and validation failures.
7. Make clear that approximately 100 findings are an initial checkpoint sample, not a general accuracy estimate.
8. Write `CHECKPOINT_REPORT.md` with:
   - architecture and current implementation;
   - which components are simplified or stubbed;
   - test method and sample selection;
   - result tables;
   - failures and limitations;
   - progress against every proposal target;
   - unmet targets;
   - changes to scope, design, model, retrieval, or validation and why;
   - next steps after the checkpoint.
9. Write `AI_USE_DISCLOSURE.md` listing the AI tools/models used, purpose, human verification performed, generated code or text retained, risks, and mitigations.
10. Ask each member to review the paragraph describing their contribution before final submission.

## Offline test

Use a tiny hand-written dataset covering:

- one genuine finding retained;
- one genuine finding wrongly dismissed;
- one false positive removed;
- one false positive retained;
- one human-review result.

Verify the expected metric counts exactly.

## Definition of done

- The evaluator produces the same metrics from the same saved inputs every time.
- The answer key never appears in an LLM request file.
- The checkpoint report includes results and failures, not only successful examples.
- The report explicitly lists all simplified, stubbed, and unmet items.
- The AI-use disclosure is complete to date.
- Every team member's contribution is visible in Git history.

## Commit example

```text
evaluation: add checkpoint metrics and failure report
```

---

# Integration Order

Wei Lin owns the final integration and submission gate. Use `Checkpoint_WEILIN_FINAL_INTEGRATION_AND_SUBMISSION.md` after the four component branches are ready. The component owners remain responsible for their own tests and explanations; Wei Lin checks that the combined system works, the evidence is recorded, and the final repository is safe to submit.

The four components should remain independently testable, but integration happens in this order:

1. Darren provides normalised alerts and the selected case list.
2. Hong Yi produces single-agent and council outputs using those alerts and common evidence.
3. Lisa validates both sets of outputs and creates safe final verdicts.
4. Bradley scores the scanner and TriageBot results against the hidden answer key and completes the report.
5. The repository owner runs the final paid OpenRouter batch with the restricted project key and records the exact model, token usage, latency, and cost.

If a component is incomplete, replace only that component with a documented fixture or stub so the end-to-end demonstration still runs. The checkpoint report must identify the stub and explain what remains.

# Final Checkpoint Checklist

- [ ] All four active members have a meaningful commit under their own Git identity.
- [ ] Wei Lin's scaffolding commits remain visible.
- [ ] README setup commands work on a clean clone.
- [ ] No `.env`, API key, restricted course PDF, raw response directory, or downloaded benchmark repository is tracked.
- [ ] One SQL-injection case runs end-to-end.
- [ ] Single-agent and council paths run on the same evidence.
- [ ] Approximately 100 findings are scored, or any shortfall is reported honestly.
- [ ] At least one failure case is explained.
- [ ] Invalid evidence is rejected or sent to human review.
- [ ] Model, versions, latency, token usage, and cost are recorded.
- [ ] `CHECKPOINT_REPORT.md` covers results, failures, progress, unmet targets, and design changes.
- [ ] `AI_USE_DISCLOSURE.md` is complete.
- [ ] Final repository scan finds no credentials.
- [ ] The final commit is pushed before the submission deadline.

# Suggested Internal Cut-offs

To preserve a submission buffer:

- **17 October, 23:59:** individual component branches and offline tests ready.
- **18 October, 12:00:** components integrated; stop adding features.
- **18 October, 18:00:** final paid run and metrics captured.
- **18 October, 21:00:** report reviewed, repository checked, and submission prepared.
- **18 October, 23:59:** official checkpoint deadline.

If time becomes tight, prioritise the end-to-end SQL-injection demonstration, saved test evidence, honest limitations, contribution history, checkpoint report, and AI-use disclosure. Do not spend the remaining time on a UI, database, full FAISS implementation, or all 2,740 benchmark cases.
