# Wei Lin — Final Integration and Submission Checklist

## Your part in simple terms

After Darren, Hong Yi, Lisa, and Bradley finish their components, you assemble the pieces and prove that the repository is ready to submit.

You are not responsible for rewriting their work. You are responsible for checking that the pieces connect, running the final evidence-producing tests, recording the results, checking the repository, and pushing the final submission.

The final flow should look like this:

```text
OWASP Benchmark case
    -> Semgrep finding
    -> normalised alert
    -> single-agent or Analyst/Skeptic/Chair review
    -> deterministic validation
    -> final verdict
    -> evaluation metrics and checkpoint report
```

The checkpoint is due on **18 October 2026 at 23:59 Singapore time**. Aim to finish the final review several hours earlier.

## When to use this file

Do not start final integration until the four members have:

- completed their assigned component;
- added their offline tests;
- made a meaningful commit under their own GitHub identity;
- pushed their branches or opened pull requests;
- explained any unfinished work or stub.

They can work independently first. You only need to use this checklist after their branches are ready.

## 1. Collect and review the four contributions

### Darren

- [ ] Semgrep JSON can be converted into the shared normalised alert format.
- [ ] OWASP case mapping is separate from the LLM-facing alert.
- [ ] Duplicates, unmapped paths, and mismatches are reported.
- [ ] The SQL-injection sample selection is repeatable and documented.
- [ ] His offline tests pass.

### Hong Yi

- [ ] The single-agent path works with offline fixtures.
- [ ] The Analyst/Skeptic/Chair path works with offline fixtures.
- [ ] Both paths use the same common evidence for comparison.
- [ ] `OPENROUTER_MODEL` controls the model, with a cheap development default.
- [ ] Model, token usage, latency, and approximate cost can be recorded.
- [ ] No answer-key label is included in prompts.

### Lisa

- [ ] Valid results pass deterministic checks.
- [ ] Invalid JSON, fabricated quotes, wrong files, bad line numbers, duplicates, missing cases, and unsupported verdicts fail safely.
- [ ] Invalid or unverifiable results become `human_review` with reasons.
- [ ] The validator works for both single-agent and council results.
- [ ] Her offline tests pass.

### Bradley

- [ ] The evaluator consumes saved scanner, model, and validated results.
- [ ] The evaluator produces deterministic metrics.
- [ ] Human review is reported separately from false-positive removal.
- [ ] Failures and limitations are recorded, not hidden.
- [ ] `CHECKPOINT_REPORT.md` is complete or ready for final results.
- [ ] `AI_USE_DISCLOSURE.md` is complete to date.

If a component is incomplete, do not silently hide it. Use a small documented fixture or stub so the demonstration can still run, and record the limitation in the checkpoint report.

## 2. Merge safely

Use pull requests or review each branch before merging. Confirm that each member's commit remains visible in Git history.

Recommended order:

1. Darren's Semgrep and mapping work.
2. Hong Yi's orchestration work.
3. Lisa's validation work.
4. Bradley's evaluation and report work.

After every merge:

```powershell
git status
git log --oneline --decorate --all -15
```

Resolve conflicts deliberately. Do not discard a teammate's work to make the merge clean.

The final `main` branch must contain meaningful commits from Darren, Hong Yi, Lisa, and Bradley, as well as the existing scaffolding commits.

## 3. Prepare a clean local environment

From the final integrated branch:

```powershell
py -m venv .venv
& '.\\.venv\\Scripts\\python.exe' -m pip install -r '.\\requirements.txt'
& '.\\.venv\\Scripts\\python.exe' '.\\verification\\openrouter_smoke.py' --self-test
```

The offline self-test must pass before any paid model call. It should reject fabricated quotes, wrong file/line citations, and malformed JSON.

If the final code needs the OWASP Benchmark, clone the external repository locally using the pinned instructions in `README.md` (Setup). The benchmark repository is intentionally not committed because it is large and includes the answer key.

Keep the local benchmark, answer key, raw Semgrep output, raw model responses, and generated results under ignored `Context/tmp/`. Never send the answer key to an AI prompt.

## 4. Run the connected demonstration

Run at least one SQL-injection case through the complete path:

```text
OWASP source
 -> Semgrep finding
 -> normalised alert
 -> common source/guidance evidence
 -> single-agent result
 -> council result
 -> Lisa's validator
 -> final verdict
```

Record the case ID, finding, evidence, single-agent result, council results, validation result, final verdict, citations, model, latency, token usage, and approximate cost.

If a live call is needed, use a low-limit temporary key or the owner's key locally. Do not commit the key. Use the cheap development model for debugging; use the proposal model, `google/gemini-3.8-flash`, only for the recorded final comparison if budget allows.

Before running paid calls, confirm the account, model, number of cases, and spending limit. Do not automatically retry a timeout or billing-uncertain request.

## 5. Run the initial evaluation

Run the agreed sample of approximately 100 SQL-injection/CWE-89 findings, or document exactly why a smaller sample was necessary.

Compare the same cases across these configurations where possible:

- **A — scanner-only:** Semgrep baseline;
- **B — single agent:** one LLM review;
- **C — council:** Analyst/Skeptic/Chair review;
- **D — validated council:** council output after Lisa's checks, if ready.

Use the answer key only in the evaluation stage. It must not appear in prompts, common evidence, role reports, or saved model request payloads.

Record:

- number of evaluated cases;
- genuine vulnerabilities and safe cases in the sample;
- genuine findings retained;
- false positives removed;
- genuine vulnerabilities wrongly dismissed;
- false positives retained;
- human-review rate;
- invalid-output rate;
- latency, token usage, and approximate cost;
- representative failures and likely causes.

Treat `human_review` as its own outcome. Do not count it as a correctly removed false positive. If the sample is smaller than approximately 100, report the shortfall honestly.

## 6. Complete the checkpoint documents

Confirm that `CHECKPOINT_REPORT.md` includes:

- [ ] current architecture and implementation;
- [ ] simplified, stubbed, deferred, and unverified components;
- [ ] test method and sample-selection rule;
- [ ] scanner baseline and TriageBot results;
- [ ] metrics and result tables;
- [ ] failures, limitations, and threats to validity;
- [ ] progress against every proposal checkpoint target;
- [ ] unmet targets and why;
- [ ] scope, design, model, retrieval, or validation changes and why;
- [ ] next steps after the checkpoint.

Confirm that `AI_USE_DISCLOSURE.md` includes the AI tools/models used, purpose, retained generated material, human verification, risks, mitigations, and OpenRouter usage/cost information.

Ask each member to review the paragraph describing their contribution.

## 7. Check repository contents and secrets

The repository should contain source code, tests, README, instructions, sanitised fixtures, and final reports. It must not contain `.env` files, API keys, private credentials, the downloaded benchmark, the answer key, raw response directories, large generated Semgrep output, restricted SMU PDFs, or virtual environments.

Run:

```powershell
git status --short
git ls-files
git diff --check
git grep -n -I -E 'sk-or-v1-[A-Za-z0-9_-]{20,}|OPENROUTER_API_KEY=[^<[:space:]]+' -- ':!Context/tmp/**' ':!.env.example'
git check-ignore -q -- .env
git check-ignore -q -- Context/tmp/BenchmarkJava
```

The key search should return no real key, and the ignore checks should succeed.

## 8. Test from a clean clone

Use a fresh clone or another teammate's machine to confirm that the repository is understandable without your private local files.

- [ ] README setup works.
- [ ] Dependencies install.
- [ ] Offline self-test passes.
- [ ] Shared Context files explain the project.
- [ ] The README does not pretend that ignored benchmark/course files are included.
- [ ] Final reports and commands use reproducible paths.

If the complete benchmark run requires a local external clone, document the pinned clone command in the README or report.

## 9. Final submission gate

- [ ] Four active members have meaningful commits under their own identities.
- [ ] Existing scaffolding commits remain visible.
- [ ] Intended teammates have repository access.
- [ ] One SQL-injection case works end-to-end.
- [ ] Single-agent and council paths use comparable evidence.
- [ ] Deterministic validation rejects unsupported evidence.
- [ ] Approximately 100 findings are evaluated, or the shortfall is documented.
- [ ] At least one success and one failure are shown.
- [ ] Metrics, model, versions, latency, token usage, and cost are recorded where available.
- [ ] `CHECKPOINT_REPORT.md` is complete.
- [ ] `AI_USE_DISCLOSURE.md` is complete.
- [ ] README and setup commands work from a clean clone.
- [ ] No credentials, restricted material, answer key, or generated bulk data is tracked.
- [ ] The final commit is pushed to `origin/main`.

## 10. Final push and handoff

After the final review:

```powershell
git status --short --branch
git add .
git commit -m "checkpoint: integrate results and prepare submission"
git push origin main
git status --short --branch
git log -1 --oneline --decorate
```

Before using `git add .`, inspect `git status` so ignored local material is not accidentally force-added.

The final handoff should state the final commit hash, repository link, offline-test command, evaluation command, sample size, main results, limitations, unmet targets, and confirmation that no key or restricted file was committed.

## If time becomes tight

Prioritise:

1. one working SQL-injection end-to-end example;
2. offline tests and safe validation;
3. honest evaluation results and failures;
4. checkpoint report and AI-use disclosure;
5. visible contributions from all members;
6. secret/restricted-file scan and clean push.

Do not spend the final hours on a user interface, database, full 2,740-case run, or unfinished feature expansion. A narrow, reproducible, honestly documented checkpoint is acceptable when limitations are clear.

