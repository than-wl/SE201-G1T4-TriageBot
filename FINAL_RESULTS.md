# TriageBot Final Evaluation

Status: frozen held-out evaluation and robustness checks complete on
2026-10-28. No model, prompt, threshold, sample, or source-window setting was
tuned after inspecting held-out outputs.

## Question and comparison

The experiment asks whether evidence-grounded LLM triage can remove Semgrep
false positives while retaining genuine vulnerabilities. It compares the
prototype against the conventional baseline: run Semgrep, keep every finding,
then require a person to review all of them. The single-agent configuration
tests the simplest LLM approach; the Analyst/Skeptic/Chair council tests whether
structured disagreement improves decisions; deterministic validation tests
whether unsupported model answers can be safely redirected to a person.

## Frozen protocol

- OWASP Benchmark Java v1.2, pinned commit
  `8b67a88d73b2594570fc21150705283de884620b`.
- Semgrep 1.178.0.
- Stratified 50/50 development/test split, seed 201.
- Held-out sample: 120 test cases, 24 each for CWE-22, CWE-78, CWE-79,
  CWE-89, and CWE-90; every category has 12 genuine and 12 false-positive
  findings.
- Model: `google/gemini-3.8-flash`, temperature 0, strict JSON schema, no
  automatic retry.
- Identical cases for scanner only, single agent, council, and validated
  council.
- A `human_review` verdict is treated as retained, not removed. Therefore the
  conventional binary metrics use:
  - true positive = genuine finding retained or sent to human review;
  - false negative = genuine finding dismissed as false positive;
  - false positive = safe finding retained or sent to human review;
  - true negative = safe finding removed.

Evidence SHA-256 values:

- recorded `p/java` scan:
  `5614cdba5382269cf1f5d3c610df08c36c14bac92fc2d4ab45467f4961ef0001`
- combined scan:
  `22a4468b67144a5bc1cb74c54da880b44fa9b5f12bf168d570f021f9ac9e4073`
- frozen model-side sample:
  `a8c5b16947d91ab5aaeb14dd033ebfd841e29855957e80e0277f92abfa8e63b1`

## Semgrep recall ceiling

These figures cover all 2,740 labelled Benchmark cases, not just cases that
Semgrep alerted on.

| Scanner configuration and scoring | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `p/java`, any alert in case | 995 | 520 | 420 | 805 | 65.7% | 70.3% | 67.9% |
| `p/java`, CWE-matched alert | 970 | 512 | 445 | 813 | 65.5% | 68.6% | 67.0% |
| Combined, any alert in case | 1,249 | 520 | 166 | 805 | 70.6% | 88.3% | 78.5% |
| Combined, CWE-matched alert | 1,224 | 512 | 191 | 813 | 70.5% | 86.5% | 77.7% |

The recorded `p/java` scan contained 1,909 test-file findings across 1,515
cases. The combined scan contained 2,166 findings; ingest retained 2,163
test-file findings across 1,769 cases and excluded three helper-file findings
from Benchmark case scoring. Semgrep reported 16 files over its 1 MB limit and
two `.semgrepignore` matches; this is recorded as a scan limitation rather than
silently treated as coverage.

The combined configuration found 254 additional genuine cases and, on this
benchmark, no additional false-positive cases. The gain comes from enabling
rules that cover categories absent from `p/java`: secure-cookie recall rose
from 0% to 100%, and weak-randomness recall rose from 0% to 100%. For the five
categories used by the held-out TriageBot sample, the two scanner
configurations produced the same category-level counts. Thus the combined scan
raises the whole-system recall ceiling, but does not change the conditional
120-case comparison.

This result does not prove that broader rules are free in real projects. The
benchmark result is unusually clean: broader rules can add duplicate,
irrelevant, or false-positive findings on production code, so scanner tuning
must be re-measured on the target repository.

Across only the five categories selected for TriageBot evaluation, Semgrep had
694 TP, 481 FP, 110 FN, and 252 TN: 59.1% precision, 86.3% recall, and 70.1%
F1. The combined rules did not change these counts. Therefore, even a perfect
downstream filter on these categories cannot raise whole-pipeline recall above
86.3%; the 110 scanner misses are unrecoverable. The held-out TriageBot table
below measures the second stage conditional on a Semgrep finding and must not
be mistaken for this whole-pipeline ceiling.

## Held-out conditional results

These results are conditional on Semgrep having raised a finding. The balanced
sample has 60 genuine and 60 false-positive findings.

| Configuration | Precision | Recall | F1 | Genuine dismissed | FP removed | Human review | Invalid | Mean latency | Cost |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Scanner only | 50.0% | 100.0% | 66.7% | 0/60 | 0/60 | 0.0% | 0.0% | n/a | n/a |
| Single agent | 83.3% | 83.3% | 83.3% | 10/60 | 50/60 | 10.0% | 0.0% | 13.455 s | US$0.445943 |
| Council | **89.1%** | 95.0% | **91.9%** | 3/60 | **53/60** | 7.5% | 0.0% | 27.177 s | US$1.472927 |
| Validated council | 85.3% | **96.7%** | 90.6% | **2/60** | 50/60 | 21.7% | 15.8% | 27.177 s | same council calls |

The council gave the best precision and F1 and removed 88.3% of false
positives, but it still wrongly dismissed 5.0% of genuine findings. Validation
changed unsupported council answers to human review, reducing genuine
dismissals from three to two at the cost of three fewer false-positive removals
and 17 additional human reviews. The final single-plus-council run cost
US$1.918870; validated council reuses the council output and therefore adds no
model cost. One single-agent call did not report token/cost usage, so the saved
configuration has usage for 119 of 120 single-agent cases; all 120 verdicts are
still scored.

## Per-category results

Each row covers 12 genuine and 12 false-positive findings.

| Configuration | CWE | Precision | Recall | F1 | Genuine dismissed | FP removed | Human review | Invalid |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Single agent | CWE-22 | 85.7% | 100.0% | 92.3% | 0 | 10 | 3 | 0 |
| Single agent | CWE-78 | 90.0% | 75.0% | 81.8% | 3 | 11 | 1 | 0 |
| Single agent | CWE-79 | 100.0% | 83.3% | 90.9% | 2 | 12 | 0 | 0 |
| Single agent | CWE-89 | 81.8% | 75.0% | 78.3% | 3 | 10 | 5 | 0 |
| Single agent | CWE-90 | 66.7% | 83.3% | 74.1% | 2 | 7 | 3 | 0 |
| Council | CWE-22 | 92.3% | 100.0% | 96.0% | 0 | 11 | 3 | 0 |
| Council | CWE-78 | 90.0% | 75.0% | 81.8% | 3 | 11 | 1 | 0 |
| Council | CWE-79 | 100.0% | 100.0% | 100.0% | 0 | 12 | 2 | 0 |
| Council | CWE-89 | 100.0% | 100.0% | 100.0% | 0 | 12 | 1 | 0 |
| Council | CWE-90 | 70.6% | 100.0% | 82.8% | 0 | 7 | 2 | 0 |
| Validated council | CWE-22 | 80.0% | 100.0% | 88.9% | 0 | 9 | 14 | 13 |
| Validated council | CWE-78 | 90.9% | 83.3% | 87.0% | 2 | 11 | 2 | 1 |
| Validated council | CWE-79 | 100.0% | 100.0% | 100.0% | 0 | 12 | 5 | 3 |
| Validated council | CWE-89 | 92.3% | 100.0% | 96.0% | 0 | 11 | 3 | 2 |
| Validated council | CWE-90 | 70.6% | 100.0% | 82.8% | 0 | 7 | 2 | 0 |

The aggregate score hides two clear weaknesses. Command injection (CWE-78)
caused all three raw-council genuine dismissals, while LDAP injection (CWE-90)
had the weakest precision and removed only seven of twelve false positives.
Validation's 19 invalid outputs comprised 18 exact guidance-metadata mismatches
and one explanation that named a source token not present in the supplied code.
Thirteen of those validation escalations were in CWE-22, suggesting that the
guidance-reference contract is too brittle for that retrieved material even
when source citations are usable.

## Representative successes and failures

- CWE-79 true positive `BenchmarkTest00030`: the council correctly traced an
  HTTP parameter-map value into `printf` in an HTML response without output
  encoding.
- CWE-79 false positive `BenchmarkTest00476`: it correctly evaluated the
  constant ternary branch and showed that untrusted input never reached the
  response sink.
- CWE-89 true positive `BenchmarkTest00024`: it correctly identified request
  input concatenated into SQL rather than bound through a placeholder.
- CWE-89 false positive `BenchmarkTest00114`: it correctly evaluated
  `294 - 86 > 200` and identified the hard-coded safe branch.
- CWE-78 failure `BenchmarkTest00983`: the council dismissed a genuine case by
  treating attacker-controlled `Runtime.exec` environment arguments as unable
  to affect command execution. Validation caught an unsupported `envp` term and
  escalated this one to human review.
- CWE-78 failure `BenchmarkTest02155`: the council similarly dismissed a
  genuine environment-array case; validation did not catch it. This is a real
  semantic blind spot, not a formatting failure.
- Several interface/helper cases remained uncertain because the bounded source
  window did not include the implementation needed to prove the data flow.
  This is evidence that a larger fixed window is not a complete substitute for
  call-aware source retrieval.

## Robustness

The five pre-declared council repeat cases had 5/5 verdict agreement in both the
raw and validated configurations. This is encouraging but is a very small
repeat sample and does not prove determinism.

The single-agent mutation check exposed a serious weakness. All five originals
were correctly labelled false positive. After each safe constant branch was
inverted so request input reached SQL, none changed to the required true
positive: three stayed false positive and two were escalated to human review.
In several outputs the explanation correctly recalculated the mutated branch
and explicitly said tainted input reached SQL, yet the JSON verdict remained
`false_positive`. Citation validation cannot catch this contradiction because
the cited text exists. This 0/5 mutation result limits any production claim and
shows that future work needs semantic consistency checks or a stronger model,
not merely more prompt text.

The mutation pairs cost US$0.035881 and the council repeats cost US$0.057454,
for US$0.093335 of robustness calls beyond the main final run.

## Why this model and architecture

`google/gemini-3.8-flash` was selected after the bounded feasibility smoke test
because it accepted strict structured output through OpenRouter, produced
source-grounded answers on real Semgrep findings, was fast enough for an
interactive prototype, and fit the team's small evaluation budget. The model
was held fixed for the frozen experiment. This is a practical choice, not a
claim that it is universally the best security model.

The conventional alternative is Semgrep followed by manual review. It has no
LLM hallucination risk, but every false positive consumes reviewer time. A
single LLM reviewer is cheaper and simpler than the council; the council adds
independent analyst and skeptic perspectives before a chair decides. The
deterministic validator is intentionally outside the model: it checks that
citations exist and converts unsupported answers to human review rather than
trusting fluent text.

## Threats to validity

- OWASP Benchmark is synthetic Java code, so the results are not a production
  accuracy estimate.
- Only five CWE categories are represented in the conditional TriageBot test.
- Balanced sampling is useful for comparison but does not reproduce a real
  repository's vulnerability prevalence; precision will change with
  prevalence.
- Public benchmark code may have appeared in model training data even though
  answer labels were never prompted.
- Temperature 0 reduces but does not eliminate non-determinism.
- Semgrep alerts are a selection filter: conditional TriageBot metrics cannot
  recover scanner false negatives. Whole-pipeline and conditional results must
  be read together.
- A valid citation establishes source support, not that the security reasoning
  is correct.

See `RESPONSIBLE_AI_RISK_ASSESSMENT.md` for the complete risk register,
mitigations, residual risks, and deployment boundary.
