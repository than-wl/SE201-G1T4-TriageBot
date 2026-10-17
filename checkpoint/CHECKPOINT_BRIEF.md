# TriageBot Checkpoint Brief

## Purpose of this document

This document summarises where the TriageBot project currently stands and what we need to do for the SE201 checkpoint. It is intended for the whole team to read before we decide the exact task allocation and implementation priorities.

The checkpoint is due on **18 October 2026 at 23:59** and is worth **5%** of the project grade. The checkpoint is progress-focused: we are not expected to have finished the entire TriageBot system yet.

## 1. What is the goal of the checkpoint?

The goal is to show that we have a **real, working, measurable foundation** for TriageBot.

In practical terms, we should be able to demonstrate:

> One complete and honest working slice of TriageBot, with the main components connected, evidence from an initial test round, and clear documentation of what is simplified or unfinished.

The checkpoint should prove five things:

1. **The project can be accessed and understood.**
   The shared repository must be readable, contain setup instructions, and show meaningful contributions from every team member.

2. **The proposed architecture has started to become a working system.**
   The important components should be connected, even if some components are simplified or stubbed.

3. **At least one core feature works end-to-end.**
   For our project, the clearest demonstration is a security finding moving through the pipeline from Semgrep, through evidence retrieval and LLM triage, to validation and a final triage outcome.

4. **Our chosen AI technique works in a limited but real setting.**
   The checkpoint does not require broad or final accuracy. It does require a working limited demonstration of the planned retrieval, tool/workflow, and multi-agent approach.

5. **We have measured progress rather than making unsupported claims.**
   We need at least one testing round, initial metrics, failures, limitations, progress against targets, design changes, and an AI-use disclosure log.

The checkpoint is therefore not “finish all of TriageBot” or “prove that the final system is accurate.” It is a progress gate showing that the proposal is feasible and that the team knows how to continue.

## 2. What do we have now?

### Repository and project organisation

- A private GitHub repository has been created for **SE201 G1T4 (TriageBot)**.
- The repository currently contains a public-facing `README.md` and verification scripts.
- Private project context, reports, PDFs, credentials-related files, and local test artefacts are kept under the ignored `Context/` folder.
- The repository has not yet demonstrated meaningful commits from every team member. This still needs to be addressed before the checkpoint.

### Semgrep baseline work

- The OWASP Benchmark Java v1.2 dataset is available locally.
- The official answer key contains **2,740 labelled cases**: 1,415 true vulnerabilities and 1,325 false positives.
- Semgrep has been run with the `p/java` ruleset.
- The run produced **1,909 findings** across **2,766 scanned files**, with no recorded scan errors and 60 rules involved.
- A preliminary filename-based match identified 1,515 benchmark cases, but this is not yet a complete or fully trustworthy evaluation mapping for every CWE category. It should be treated as baseline evidence, not as the final scorecard.

This means we have started the scanner baseline, but we still need to turn it into a clean, documented scorecard aligned with the official answer key.

### OpenRouter and LLM feasibility

- OpenRouter access has been successfully tested with the planned Gemini model, `google/gemini-3.8-flash`.
- The model returned valid structured JSON for five real SQL injection benchmark cases.
- The five cases included three true vulnerabilities and two false positives.
- All five responses included citations that matched the expected source files and lines in the test harness.
- The mean response time was approximately 9.87 seconds, with a measured range of 8.16 to 11.72 seconds.
- The initial five-case smoke test cost approximately **US$0.00993**.

This shows that the model can be called reliably and can produce the response format we need. It does not yet prove general accuracy across the benchmark.

### Initial council workflow

- A limited Analyst–Skeptic–Chair workflow has been exercised on the same five SQL injection cases.
- The three roles produced valid cited outputs.
- The Chair's labels matched the benchmark labels for all five cases in this small test.
- The additional council test cost approximately **US$0.03405**.

This is useful feasibility evidence for the proposed multi-agent design. It is not enough to claim that the council is accurate in general.

### Evidence retrieval and validation

- OWASP SQL injection guidance can be retrieved over HTTPS.
- A standard-library keyword retrieval fallback is working.
- The current environment does not have `sentence_transformers` or `faiss` installed, so the planned embedding/vector-store retrieval is not yet implemented in the tested environment.
- Existing helpers can extract useful source evidence such as APIs, sinks, string concatenations, guards, and constants for the five tested cases.
- A deterministic validator can reject fabricated citations, wrong file/line references, and malformed JSON in self-tests.

The validator is still limited. It does not yet fully check semantic source-to-sink reasoning, automatically suppress findings, or consistently force uncertain cases into human review.

### Overall assessment

We have a credible feasibility foundation:

`Semgrep → evidence extraction/retrieval → OpenRouter model → Analyst/Skeptic/Chair outputs → basic citation validation`

However, the current evidence is still a **small smoke test**, not yet a checkpoint-ready prototype. The main gap is connecting this work into a reproducible demonstration and measuring it on approximately 100 findings, as promised in the proposal.

## 3. What must we do now to achieve the checkpoint successfully and do it well?

### A. Make one complete demonstration path work

We should prioritise one vulnerability category, most sensibly SQL injection, and make the complete path demonstrable:

`OWASP Benchmark case → Semgrep finding → normalised alert → source/guidance evidence → Analyst → Skeptic → Chair → deterministic validation → final triage result`

The demonstration should work from a documented command or script that another team member can run. It does not need every planned feature, but it must clearly show the core idea of TriageBot.

Any simplified component must be labelled honestly. For example, keyword retrieval may be used as a temporary replacement for SentenceTransformers + FAISS, and a simplified validator may be used instead of the final safety layer.

### B. Produce the required initial evaluation

We need to evaluate approximately **100 scanner findings**, preferably using a clearly defined sample of the OWASP Benchmark cases.

The evaluation should record at least:

- number of cases tested;
- true vulnerabilities and false positives in the sample;
- Semgrep/scanner-only baseline results;
- TriageBot results;
- genuine findings retained;
- false positives removed;
- genuine vulnerabilities wrongly dismissed;
- cases sent to human review;
- invalid or unsupported outputs;
- latency and approximate token/cost usage;
- failures and representative examples.

The results do not need to meet the final project targets yet. A good checkpoint report can say that a target was not met, as long as the result is measured and explained.

The evaluation mapping must use the official answer key carefully. Filename matching alone should not be presented as a complete category-independent correctness method.

### C. Prepare the checkpoint document

The checkpoint submission should clearly include:

1. what the proposal promised;
2. what has been implemented;
3. the architecture and which parts are simplified or stubbed;
4. the testing method and dataset/sample selection;
5. the initial results and metrics;
6. failures, limitations, and likely causes;
7. progress against every checkpoint target;
8. scope, design, or technology changes and why they were made;
9. the next steps after the checkpoint;
10. the AI-use disclosure log to date.

The report should distinguish clearly between:

- **verified:** directly tested and supported by recorded evidence;
- **partially verified:** works in a small or limited test;
- **not yet verified:** planned but not tested;
- **blocked or deferred:** currently not practical, with the reason stated.

### D. Make the repository checkpoint-ready

Before submission, the repository should have:

- a README with prerequisites, setup, environment variables, commands, and expected outputs;
- a reproducible offline/self-test path where possible;
- the scripts and reports needed to understand the checkpoint evidence;
- no API keys, secrets, or private credentials committed;
- commit history showing meaningful work from **all team members**;
- a clear place for the checkpoint report and AI-use disclosure.

Each team member should make a real, reviewable contribution related to their assigned role. The purpose is not to create artificial commits; it is to show genuine collaboration and make each person's work visible.

### E. Keep the scope realistic

For this checkpoint, we do **not** need to finish:

- the entire 2,740-case benchmark evaluation;
- final production-level accuracy;
- the complete embedding/vector-store implementation if it cannot be made reliable in time;
- every planned vulnerability category;
- a polished user interface;
- the final human-review workflow;
- proof that the final success targets have already been achieved.

The best use of time is to make one narrow path reliable, measure it honestly, and document the remaining work. A small but reproducible end-to-end prototype is stronger checkpoint evidence than many disconnected unfinished components.

## Suggested definition of “checkpoint done well”

We should consider the checkpoint in good shape when a teammate or instructor can:

1. clone or access the repository and follow the README;
2. run the documented demonstration;
3. see a Semgrep finding become a cited TriageBot decision;
4. understand which parts are real and which are simplified;
5. inspect results from approximately 100 evaluated findings;
6. see both successes and failures;
7. verify what each team member contributed;
8. read an honest checkpoint report and AI-use disclosure.

## Immediate team discussion points

Before implementation continues, the team should agree on:

- whether SQL injection is the single end-to-end demonstration category;
- which approximately 100 findings will be evaluated;
- what “human review” means in the checkpoint prototype;
- whether keyword retrieval is acceptable as the documented temporary fallback;
- the minimum validation checks required before a result is shown as final;
- who owns the pipeline, evaluation, report, README, and AI-use log;
- the deadline for code freeze, results capture, and report review.

## Source documents

- `Context/SE201_2026T1_project_v1.02.pdf` — project brief and checkpoint requirements.
- `docs/proposal/G1T4_Proposal.pdf` — submitted project proposal and checkpoint targets.
- `docs/feasibility/FEASIBILITY_CHECK_REPORT.md` — current feasibility and council-test evidence.
- `docs/feasibility/OPENROUTER_SMOKE_REPORT.md` — OpenRouter five-case smoke-test evidence.
- `Context/Codex Handoff.md` — project handoff and current operating context.
