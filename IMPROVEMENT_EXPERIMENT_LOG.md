# TriageBot Improvement Experiment Log

This file records what we change, why we change it, and whether it actually
improves TriageBot. Keep failed experiments: they are useful evidence, not
something to hide.

## Rules for fair comparison

- Develop only with development cases and the five existing mutation pairs.
- Do not tune using the completed 120-case held-out results.
- Change one main idea at a time so we know what caused the result.
- Compare every version with the same cases, model and temperature.
- Record precision, recall, F1, genuine dismissals, false positives removed,
  human-review rate, invalid outputs, cost and latency.
- Use a new set of unused test cases for the next final evaluation.

## Original baseline

| Measure | Original result |
| --- | ---: |
| Council F1 | 91.9% |
| Council genuine vulnerabilities wrongly dismissed | 3 of 60 |
| Council false positives removed | 53 of 60 |
| Council human review | 9 of 120 |
| Validated-council genuine vulnerabilities wrongly dismissed | 2 of 60 |
| Validated-council human review | 26 of 120 |
| Single-agent mutation verdicts correctly changed | 0 of 5 |
| Repeat-case agreement | 5 of 5 |

Important observations:

- Some mutation explanations recognised that tainted input reached SQL, but
  the final verdict still said `false_positive`.
- Validation increased human review from 9 to 26 cases. Eighteen of the
  nineteen invalid outputs were exact OWASP guidance-metadata mismatches.
- Some reports lacked helper-method source code outside the fixed window.
- Command injection caused the most dangerous mistakes; LDAP injection left
  the most false positives.

## Improvement plan

### Experiment 1 - Structured reasoning and consistency repair

**Problem:** the explanation can contradict the final verdict.

**Change:** require the Chair to complete a small security worksheet:

- source of untrusted input;
- dangerous sink;
- whether input reaches the sink;
- relevant guard or sanitiser;
- whether that protection is effective; and
- verdict.

If the worksheet and verdict conflict, ask the Chair once to reconsider the
specific contradiction. If it still conflicts, return `human_review`.

**Where it fits:** keep the current Council and pipeline. Extend the shared
report contract, Chair output and structured OpenRouter schema, then check the
worksheet at the validator seam.

**Success target:** no mutated vulnerable case may remain `false_positive`;
aim for at least 4 of 5 to become `true_positive`, with the remainder going to
human review. Genuine dismissals on the fixed development set must not rise.

**Status:** Implemented and tested. Result: mixed; keep as a bounded safety guard,
but use the Council as the recommended review path.

### Experiment 2 - Repair validation failures instead of immediately escalating

**Problem:** minor evidence-formatting mistakes create unnecessary human work.

**Change:** classify validation results:

- **Unsafe:** fabricated/missing source evidence or unresolved contradiction ->
  human review.
- **Repairable:** wrong guidance metadata or correctable citation formatting ->
  repair the specific field once, then validate again.
- **Valid:** accept the verdict.

Exact guidance metadata should be normalised from the retrieved chunk because
the correct value is already known. Use a targeted model repair only when human
judgment is needed; do not rerun the entire council.

**Where it fits:** deepen `validate_results()` behind its existing interface.

**Success target:** reduce validated human review below 26 of 120 without
increasing genuine dismissals above 2 of 60 on the comparison set.

**Status:** Implemented. Development check passed; full held-out effect is not
yet measured.

### Experiment 3 - Graph-based source retrieval

**Problem:** a fixed line window can omit helper methods and indirect data flow.

**Change:** build a lightweight code graph that retrieves:

- the method containing the alert;
- methods it directly calls;
- relevant same-project helper implementations; and
- the path from likely input source to sink when available.

Use graph relationships for correctness. Vector similarity may rerank or add
related context later, but it must not replace real caller/callee relationships.

**Where it fits:** deepen `build_payload()` behind its current interface. The
Council and CLI should not need to know how the context was found.

**Success target:** all known truncated-helper cases include the required
method, context stays within the token budget, and missing-context human reviews
fall without increasing genuine dismissals.

**Status:** Implemented. Focused development check passed; broader accuracy
effect remains for the new held-out comparison.

### Experiment 4 - CWE-specific reasoning

**Problem:** one general prompt performs unevenly across vulnerability types.

**Change:** add short specialist checklists for command injection and LDAP
injection first. Reuse the same agents and output contract.

**Where it fits:** select a checklist from the alert CWE inside the existing
review prompt module.

**Success target:** command-injection genuine dismissals and LDAP false-positive
retention both decrease on fixed development cases without worsening other
categories.

**Status:** Implemented and covered by offline routing tests. Accuracy effect is
not yet measured.

### Experiment 5 - New final comparison

After Experiments 1-4 pass their development checks, run the original and
improved architectures on the same new, unused held-out sample. Report both
versions, including any regressions.

**Status:** Sample frozen; paid original-versus-improved runs not yet started.

## Experiment results

### 2026-10-28 - Experiment 1

**Change:** added a structured source/sink/protection worksheet and one bounded
consistency repair. A second contradiction becomes `human_review`. The same
guard now applies to both single-agent and Council review.

**Cases used:** the five pre-declared development mutation pairs, with the same
Gemini 3.8 Flash model and temperature 0. The unchanged Council at commit
`9c0be69` was rerun on the same pairs for a fair baseline.

| Run | Safe originals kept as false positive | Vulnerable mutations true positive | Vulnerable mutations not dismissed |
| --- | ---: | ---: | ---: |
| Original single-agent baseline | 5/5 | 0/5 | 0/5 |
| Structured single-agent, before shared repair | 5/5 | 0/5 | 2/5 |
| Structured single-agent with shared repair | 3/5 validated (5/5 raw) | 1/5 | 4/5 |
| Unchanged Council (`9c0be69`) | 5/5 | 5/5 | 5/5 |
| Structured Council | 3/5 validated (5/5 raw) | 4/5 validated (5/5 raw) | 5/5 |

The structured Council had three invalid outputs because exact OWASP guidance
metadata did not match the retrieved chunks. Its raw security decisions were
still correct in all 10 runs. This is the target of Experiment 2.

**Cost and latency:** unchanged Council: US$0.1131 reported cost and 24.17 s
average latency per case; structured Council: US$0.1248 and 28.32 s. These are
small development runs, so they show direction rather than a stable estimate.

**Improved?** Mixed. The guard reduced dangerous single-agent dismissals, but
did not meet the zero-dismissal target. The Council already handled all five
mutations correctly, so the earlier 0/5 mutation result must not be described
as a Council failure.

**Decision:** keep the small consistency guard as defence in depth. Keep the
single agent as an experimental baseline. Use the Council as the recommended
path, and do not claim an accuracy gain from Experiment 1 without a larger
comparison.

**Unexpected finding:** changing the comparison from single agent to Council
had a much larger effect than adding a repair retry. Fair baselines changed the
architectural conclusion.

### 2026-10-28 - Experiment 2

**Change:** known OWASP guidance references now keep their model-selected
`chunk_id` but copy the authoritative document name, section and URL from the
retrieved chunk. Every change is recorded in `validation_repairs`. Unknown
chunk IDs, malformed guidance and unsupported source citations still fail.

**Cases used:** the same five development mutation pairs, producing 10 Council
outputs in total.

**Before:** the structured-Council Experiment 1 run made all 10 raw security
decisions correctly, but three outputs became human review because guidance
metadata did not exactly match the retrieved chunk.

**After:** 5/5 safe originals remained false positives, 5/5 vulnerable
mutations became true positives, and invalid outputs fell from 3 to 0. Two
outputs were normalised and recorded instead of escalated.

**Cost and latency:** US$0.1283 reported cost and 24.92 s average latency per
case for this 10-case run. Metadata normalisation itself is local code and adds
no model call.

**Improved?** Yes on the fixed development check.

**Decision:** keep. It removes avoidable human work without weakening source
or chunk-ID verification. The target of reducing 26 held-out human reviews is
not yet claimed; that requires the new final comparison.

**Unexpected finding:** the model repeatedly selected the correct OWASP chunk
while varying only its copied title or section. Treating retrieval identity and
display metadata as equally dangerous had created unnecessary escalations.

### 2026-10-28 - Experiment 3

**Change:** the context builder now adds directly called same-file methods and
a bounded Java relationship graph for project classes. Factory dependencies,
interfaces and nearby implementations are followed transitively. Related files
retain real filenames and line numbers, and the validator verifies citations
against those files. Generic infrastructure classes ending in `Helper`, `Util`
or `Utils` are skipped as retrieval noise, not as a security verdict rule.

**Cases used:** all 100 checkpoint development alerts for an offline context
budget check, plus `BenchmarkTest00198` as a focused development case. The
answer key was used only after selection to score the result and was never sent
to the model.

**Before:** the old Council returned `human_review` for `BenchmarkTest00198`,
explicitly because the `ThingInterface` implementation was absent. The old run
used 6,786 prompt tokens, cost US$0.009552 and took 34.437 s.

**After:** the retriever supplied `ThingFactory`, `ThingInterface`, `Thing1`
and `Thing2`. The optimized Council returned a validated `true_positive`, which
matches the development label. It used 10,487 prompt tokens, cost US$0.014023
and took 25.936 s.

Across the 100 development alerts, 12 received related source. The final bound
was four files and 47 nonblank related lines; the largest evidence block was
about 3,526 tokens using a conservative four-characters-per-token estimate.

**Improved?** Yes for the focused missing-context case. Cost increased by about
47% for that case, so selective retrieval is essential. Broader precision and
recall effects are not yet claimed.

**Decision:** keep the graph-first retrieval seam and current bounds. Do not
add vector retrieval yet; structural Java relationships already solve the
observed development case and are easier to verify.

**Unexpected finding:** the first graph draft retrieved six files and 15,485
prompt tokens because database infrastructure crowded the context. Dependency
prioritisation and noise filtering reduced this to four files and 10,487
prompt tokens while preserving the correct verdict.

### 2026-10-28 - Experiment 4

**Change:** added short trusted-system checklists for CWE-78 command injection
and CWE-90 LDAP injection. They explicitly distinguish command strings from
arguments/environment arrays, shell interpretation from direct execution,
LDAP escaping from generic encoding, and direct flow from collection/helper
transformations. The existing Analyst, Skeptic, Chair and single reviewer are
reused.

**Cases used:** offline pipeline fixtures for both CWE routes.

**Before:** every vulnerability type used only the general review method.

**After:** the correct checklist is present in the trusted system prompt for
each target CWE. The complete 189-test offline suite passes.

**Cost and latency:** no additional model call; only a small prompt suffix.

**Improved?** Routing and architecture: yes. Precision, recall and F1: not yet
measured.

**Decision:** keep for the new held-out comparison. Remove or revise a
checklist if the comparison shows no benefit or a category regression.

**Unexpected finding:** none claimed yet; live evaluation is deliberately
deferred so the result is measured on fixed cases rather than tuned case by
case.

### 2026-10-28 - Experiment 5 preparation

The comparison sample is frozen under ignored `Context/tmp/comparison/`. It
contains 66 label-free test-partition alerts and has zero overlap with the
completed 120-case evaluation:

- 16 each for CWE-22, CWE-78, CWE-79 and CWE-89 (8 genuine and 8 safe);
- 2 for CWE-90 (the only remaining unused genuine and safe cases).

The answer-key labels appear only in the ignored aggregate manifest, never in
the model-side `selected_alerts.json`. The smaller CWE-90 stratum must be
reported as a limitation; it is not large enough for a reliable category-level
claim.

The paid comparison is complete. Commit `9c0be69` and the improved working
tree were run on this exact sample with `google/gemini-3.8-flash`, temperature
0.0 and the same response limit.

### 2026-10-28 - Experiment 5 result

**Change:** compare the complete old and improved validated pipelines. The
improved pipeline adds bounded related-source retrieval, CWE-specific review
checklists, verdict-reasoning consistency repair and targeted validation
repair.

**Hypothesis:** those changes will improve the final validated result without
sacrificing genuine-vulnerability recall or increasing human review.

**Cases used:** the frozen 66-case unused test sample above: 33 genuine
findings and 33 false positives. Neither run exposed answer-key labels to the
model.

| Validated result | Old `9c0be69` | Improved | Change |
| --- | ---: | ---: | ---: |
| Precision | 90.9% | 100.0% | +9.1 points |
| Recall | 90.9% | 93.9% | +3.0 points |
| F1 | 90.9% | 96.9% | +6.0 points |
| Genuine wrongly dismissed | 3 | 2 | -1 |
| False positives removed | 30 of 33 | 33 of 33 | +3 |
| Human review | 11 of 66 (16.7%) | 1 of 66 (1.5%) | -10 cases |
| Invalid outputs | 11 of 66 (16.7%) | 1 of 66 (1.5%) | -10 cases |
| Mean latency | 23.728 s | 26.773 s | +3.045 s |
| Reported cost | $0.804441 | $0.935804 | +$0.131363 |

**Before:** the old validated pipeline left three genuine vulnerabilities
wrongly dismissed, removed 30 false positives and escalated eleven cases.

**After:** the improved validated pipeline left two genuine vulnerabilities
wrongly dismissed, removed all 33 false positives and escalated one case. The
raw councils happened to have the same 95.2% F1; the clear gain appears in the
complete validated pipeline, where the improved evidence and repair path no
longer turns many otherwise useful decisions into invalid outputs.

**Cost and latency:** the successful improved run cost $0.131363 more and was
3.045 seconds slower per case on average. The first old-version attempt also
crashed late on a truncated HTTP response and produced no report; its partial
cost is unavailable from the local evaluator. A single clean retry completed.

**Improved? Yes overall, with a remaining safety limitation.** The integrated
pipeline improved precision, recall, F1, false-positive removal and human-review
workload on unseen cases. It still dangerously dismissed two genuine command
injection findings, so it is not safe to operate without human oversight.

**Decision:** keep the architecture. Analyse the two remaining command-
injection misses before any further tuning, and preserve this frozen result as
the unbiased comparison rather than rerunning it after changes.

**Unexpected finding:** a cheap screening run with
`google/gemini-2.5-flash-lite` was not a usable architecture measurement: 43
answers were unparseable, 10 calls returned HTTP 429, and 53 of 66 cases went
to human review. Model capability and provider reliability materially affect
the pipeline. The old runner's uncaught truncated-response crash also exposed
an operational reliability weakness absent from the completed improved run.

Add one entry after every experiment:

```text
Date:
Change:
Hypothesis:
Cases used:
Before:
After:
Cost and latency:
Improved? Yes / No / Mixed
Decision: Keep / Revise / Remove
Unexpected finding:
```

## Presentation-worthy notes

Keep short evidence-backed points here as they appear.

1. **Evaluation changed the design.** The original benchmark score looked
   strong, but mutation testing revealed a verdict-reasoning contradiction that
   aggregate F1 did not expose.
2. **Safety has a workload cost.** Validation reduced dangerous dismissals from
   three to two, but increased human review from 9 to 26.
3. **Not every validation failure is equally serious.** Eighteen of nineteen
   invalid outputs were guidance-metadata mismatches, motivating targeted repair
   instead of blanket escalation.
4. **The project follows an evidence-driven engineering cycle:** build, measure,
   find failure modes, improve one seam at a time, and compare again.
5. **Experimental controls changed the conclusion.** The original 0/5 mutation
   result was a single-agent result. On the same five pairs, the unchanged
   Council correctly classified all five vulnerable mutations, showing that
   architecture choice mattered more than the retry mechanism.
6. **Deterministic repair can beat another AI call.** On the development run,
   copying authoritative metadata from already-retrieved OWASP chunks reduced
   invalid outputs from three to zero at no extra model-call cost.
7. **More context is not automatically better.** Graph retrieval fixed a real
   missing-helper decision, but an unfiltered graph more than doubled the old
   prompt. Bounded, relationship-prioritised retrieval kept the useful factory
   chain and removed unrelated infrastructure.
8. **The controlled comparison supports the redesign.** On the same 66 unseen
   cases and Gemini 3.8 Flash model, validated F1 increased from 90.9% to 96.9%
   while human review fell from 16.7% to 1.5%. This gain cost about $0.13 and
   three seconds more per case, and two unsafe dismissals still remain.
9. **A cheaper model was not automatically cheaper in engineering terms.**
   Flash Lite cost only $0.11, but malformed and rate-limited answers sent
   80.3% of cases to humans; Gemini 3.8 Flash produced usable structured output
   and reduced that rate to 1.5% in the improved pipeline.
