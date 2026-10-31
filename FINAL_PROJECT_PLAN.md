# TriageBot Final Project Plan

Status: gates 1-5 complete; frozen held-out evaluation finished without tuning.

## Highest-band quality gate

Every final change and claim must support at least one of these official
"Accomplished" outcomes:

1. **Problem and rational use of AI:** clearly define the SAST false-positive
   problem, justify the selected model, and compare TriageBot with conventional
   scanner-plus-manual-review work.
2. **Technical design and implementation:** demonstrate a reliable,
   well-featured end-to-end prototype that directly addresses that problem.
3. **Evaluation and evidence:** use relevant metrics and datasets, report
   detailed results, and explain where and why the system succeeds or fails.
4. **Responsible AI:** provide a comprehensive AI-use disclosure and risk
   assessment with concrete mitigations and residual risks.
5. **Team collaboration:** preserve visible contributions and deliver complete,
   high-quality work on time.

Presentation and individual Q&A are assessed separately. They will be prepared
from the evidence produced here; they cannot compensate for missing evidence.

## Frozen final evaluation

The final evaluation is fixed before inspecting any TriageBot result on the
held-out cases.

- **Dataset:** OWASP Benchmark Java v1.2 at the pinned repository commit.
- **Scanner input:** committed Semgrep 1.178.0 `p/java` scan, plus one separately
  recorded higher-recall scan using `p/java` and `p/security-audit` together.
- **Split:** existing 50/50 split, stratified by Benchmark category and label,
  seed 201. Development cases remain available for fixes; final scoring uses
  only the held-out `test` partition.
- **Final sample:** 120 CWE-matching Semgrep findings, 24 from each category:
  SQL injection (CWE-89), cross-site scripting (CWE-79), path traversal
  (CWE-22), command injection (CWE-78), and LDAP injection (CWE-90). Each
  category contains 12 genuine and 12 false-positive findings. Selection is
  deterministic and uses seed 201.
- **Configurations on identical cases:** scanner only; single LLM agent;
  Analyst/Skeptic/Chair council; council plus deterministic validation.
- **Recorded model:** `google/gemini-3.8-flash`, temperature 0, structured JSON
  output, no automatic retry after a billing-uncertain failure.
- **Primary metrics:** precision, recall, F1, genuine findings wrongly
  dismissed, false positives removed, and human-review rate.
- **Operational metrics:** invalid-output rate, latency, token usage, and cost.
- **Required views:** overall results, per-category results, whole-pipeline
  performance, and TriageBot's conditional performance on Semgrep findings.
- **Robustness checks:** selected mutation pairs whose correct verdict changes,
  plus repeat runs on a small pre-declared subset to show model variation.

Robustness cases fixed before those calls:

- Development mutation pairs: `BenchmarkTest00104`, `BenchmarkTest00329`,
  `BenchmarkTest00333`, `BenchmarkTest00517`, and `BenchmarkTest01095`. Each
  safe branch condition is inverted so request-controlled input reaches the SQL
  construction; expected verdict changes from false positive to true positive.
- Held-out repeat subset: `BenchmarkTest00011` (CWE-22),
  `BenchmarkTest00015` (CWE-78), `BenchmarkTest00030` (CWE-79),
  `BenchmarkTest00024` (CWE-89), and `BenchmarkTest00021` (CWE-90).

The answer key is evaluation-side only. It may select a balanced sample and
score saved outputs, but no answer-key field or label may enter a prompt.
Settings will not be tuned after final-test outputs are inspected. Any later
change requires a clearly labelled new experiment rather than replacement of
the frozen result.

## Work gates

### Gate 1 - Experiment lock

- [x] Dataset, split, categories, sample size, configurations and metrics fixed.
- [x] Top-band rubric recorded in this file.
- [x] Deterministic final-sample command and isolation tests pass.

### Gate 2 - Reliability

- [x] Known truncated-helper failure is covered by a failing test and fixed.
- [x] OpenRouter structured output is covered by a failing test and fixed.
- [x] Full offline suite passes (183 tests on 2026-10-28).
- [x] One live development case passes before final paid calls.

### Gate 3 - Semgrep bottleneck

- [x] Higher-recall scan is recorded reproducibly.
- [x] Both scanner configurations have precision, recall and F1.
- [x] Recall ceiling and additional false-positive load are explained.

### Gate 4 - Final evaluation

- [x] Frozen 120-case held-out sample is generated.
- [x] All four configurations cover the same cases.
- [x] Mutation and repeat checks are complete.
- [x] Raw outputs remain ignored; reproducible summaries are retained.

### Gate 5 - Analysis and responsible AI

- [x] Overall and per-category metrics are reported.
- [x] Representative successes and failures are explained.
- [x] Model choice and conventional alternative are justified.
- [x] Risks cover hallucination, security, privacy, bias, intellectual
  property, prompt injection, benchmark memorisation, cost and provider
  dependence, with mitigations and residual risks.
- [x] Claims distinguish preliminary evidence from general performance.

## Scope discipline

Do not add a GUI, database, framework, embedding stack, or unrelated feature
before all five gates pass. These do not directly close a highest-band gap.
