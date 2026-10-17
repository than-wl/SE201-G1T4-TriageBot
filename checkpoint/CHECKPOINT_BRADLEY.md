# Bradley — Evaluation Harness and Checkpoint Report

## Your part in simple terms

You measure whether TriageBot helped.

You take the hidden OWASP answer key, the scanner results, and the AI/validator results, then calculate clear metrics. You also write the checkpoint report honestly: what worked, what failed, what is still a stub, and what the team should do next.

Your work turns the implementation into evidence that can be presented for the checkpoint.

```text
answer key + scanner/AI results -> metrics -> failures, limitations, and checkpoint report
```

## What you own

Suggested files:

- `verification/evaluate.py`
- `verification/tests/test_evaluate.py`
- `CHECKPOINT_REPORT.md`
- `AI_USE_DISCLOSURE.md`

Do not change the prompts or send the answer key into the AI workflow. Darren prepares the mapping; you use it only on the evaluation side.

## What you need to produce

1. A repeatable evaluator for the scanner and TriageBot configurations.
2. Metrics for the same cases across all configurations.
3. A small offline evaluation test with known expected counts.
4. `CHECKPOINT_REPORT.md` covering results, failures, progress, unmet targets, and design changes.
5. `AI_USE_DISCLOSURE.md` covering AI tools, models, purposes, human verification, risks, and mitigations.

Compare these configurations where the data is available:

- A: Semgrep/scanner-only baseline;
- B: single LLM agent;
- C: Analyst/Skeptic/Chair council;
- D: council plus deterministic validation, if integration time permits.

## How to do it

1. Read `README.md`, `CHECKPOINT_BRIEF.md`, and the proposal under `docs/proposal/`.
2. Define one input format for answer-key labels, scanner results, model results, and validated results.
3. Keep the answer key in evaluation-only code and files. Never include it in prompts or common evidence.
4. Ensure B and C use the same cases and equivalent evidence access.
5. Calculate at least:
   - number of evaluated findings;
   - genuine findings retained;
   - false-positive alerts removed;
   - genuine vulnerabilities wrongly dismissed;
   - human-review rate;
   - invalid-output rate;
   - latency, token usage, and approximate cost where available.
6. Treat `human_review` separately. Do not count it as a correctly removed false positive.
7. Include representative failures: wrong verdicts, unsupported citations, missing context, and validation failures.
8. State clearly that approximately 100 findings are an initial checkpoint sample, not a general accuracy estimate.
9. Write the checkpoint report with:
   - current architecture and implementation;
   - simplified or stubbed components;
   - sample selection and test method;
   - result tables;
   - failures and limitations;
   - progress against every proposal target;
   - unmet targets;
   - changes to scope, design, model, retrieval, or validation and why;
   - next steps after the checkpoint.
10. Ask each teammate to verify the paragraph describing their contribution.

## Your offline test

Use a tiny hand-written dataset containing:

- one genuine finding retained;
- one genuine finding wrongly dismissed;
- one false positive removed;
- one false positive retained;
- one human-review result.

Verify the expected metric counts exactly and confirm that running the evaluator twice produces the same results.

## Do you need to wait?

No. Start immediately with the tiny hand-written dataset and saved feasibility evidence.

For the final report, you will need Darren's answer-key mapping and the outputs from Hong Yi and Lisa. Do not wait idle for those files: build the evaluator and report structure first, then connect the real inputs when they arrive.

## OpenRouter key

You do not need an OpenRouter key for your assigned work. Evaluation should consume saved outputs and must run offline.

The project owner should run the final paid comparison after integration, or provide sanitised saved outputs. Repository access does not provide access to the owner's OpenRouter account or key. Never put a key in the evaluator, report, GitHub, or committed evidence.

## Definition of done

- [ ] The evaluator gives deterministic metrics from the same saved inputs.
- [ ] The answer key never appears in an LLM request file.
- [ ] The report includes results and failures, not only successful examples.
- [ ] Simplified, stubbed, and unmet items are explicitly listed.
- [ ] The AI-use disclosure is complete to date.
- [ ] Every team member's contribution is visible in Git history.
- [ ] No credential, raw response, or restricted course material is committed.
- [ ] You make at least one meaningful commit under your own Git identity.

## Git workflow

```powershell
git switch -c checkpoint/bradley-evaluation
# implement and test your component
git add verification CHECKPOINT_REPORT.md AI_USE_DISCLOSURE.md
git commit -m "evaluation: add checkpoint metrics and failure report"
git push -u origin checkpoint/bradley-evaluation
```

Ask for review or open a pull request after the offline test passes.

