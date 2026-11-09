# Improvements and changes to make

Working notes from the pre-submission review. Each item gives the problem,
why it matters and the proposed change.

## 1. End-to-end recall is low: make Semgrep flag more

**Problem.** TriageBot can only keep or dismiss alerts that Semgrep raises,
so Semgrep's recall is the ceiling for the whole system. With the committed
`p/java` scan, Semgrep catches 68.6% of the Benchmark's real vulnerabilities.
Even a perfect TriageBot cannot exceed about 69% end-to-end recall. Our
headline "100% recall" is measured only on alerts Semgrep already flagged
(the second-stage view), not on the whole system.

**Instructor feedback.** In his proposal feedback, the professor said the
first stage should be tuned for more false positives, because vulnerabilities
Semgrep misses cannot be recovered. He also asked us to compare
second-stage performance with overall performance, to see whether Semgrep is
the bottleneck.

**Current state.**
- Every TriageBot evaluation uses the `p/java` scan only.
- `FINAL_RESULTS.md` says a broader configuration raised recall from 70.3%
  to 88.3%. There is no committed scan file, ruleset or command behind that
  figure, and its 70.3% baseline does not match the README's 68.6%.
- TriageBot was never run on the broader scan.

**Proposed changes (cheapest first).**
1. Document and commit the broader scan: the rulesets used (for example
   `p/java` + `p/security-audit` + `p/owasp-top-ten`), the command and the
   output JSON. Explain the difference between 70.3% and 68.6%.
2. Score the broader scan with `python -m triagebot baseline --semgrep <file>`.
   This makes no LLM calls. Report the trade-off: how much recall rises and
   how many extra false alarms reach TriageBot.
3. Run TriageBot on a small sample of the broader scan's extra alerts, then
   report end-to-end recall (Semgrep recall x TriageBot second-stage recall)
   next to the second-stage figures.
4. Optional: add custom rules for the blind spots, weak randomness (0 of 218)
   and insecure cookies (0 of 36), and raise Semgrep's taint-analysis
   timeouts (291 to 325 fixpoint timeouts per scan).

**Presentation.** Show both views, clearly labelled: "second stage, given
Semgrep's alerts" and "end-to-end system".

## 2. Replace the CWE map with better guidance retrieval (Route 1: performance upgrade)

**Decision.** Keep the scope at the OWASP Benchmark's 11 CWE categories, and
present the final work as a performance upgrade over the checkpoint, not as a
scope expansion. Expanding the scope cannot be evaluated, because there is no
ground truth outside the 11 categories.

**State the progression accurately.** The checkpoint tested one category
(CWE-89, 100 cases) with the CWE map. The final runs tested 5 and then 6
categories on frozen, unseen samples. The upgrade improves guidance retrieval
for the same scope.

**Problem: weaknesses of the current CWE map** (`kb/cwe_map.json`, the default
`RETRIEVAL_MODE = "map"`).
1. Coverage gaps: 5 of the 11 Benchmark CWEs (330, 327, 328, 501, 614) have
   no entry, so the validator always sends those cases to human review.
2. Hard to expand: every new document needs a manual CWE mapping edit.
3. Coarse: it maps a CWE to whole documents, then ranks chunks by keyword
   counts.
4. Unverified and sometimes wrong links, for example CWE-22 (path traversal)
   maps to the File Upload sheet.
5. Measured weaker (design decision 21, dev split): P@2 is 0.39 for the map
   against 0.61 for semantic retrieval. For CWE-89, the map returned the
   primary SQL sheet for 0 of 100 dev alerts.
6. Every alert of the same CWE gets the same guidance, whatever the code does.

**Proposed changes.**
- A. Make semantic retrieval the default (already built). A new document
  needs only chunk-and-sync, not a mapping edit.
- B. Expand the knowledge base with MITRE CWE entries, SEI CERT Java rules
  and Java API documentation, to cover CWE-501, 330, 327, 328 and 614.
- C. Optional hybrid: filter chunks by CWE tags, then rank them by embedding.
- D. Optional code-aware query: CWE text plus the sink and sanitiser APIs
  found in the code.
- E. Choose `SEMANTIC_MIN_SCORE` on the dev split. Below it, send the case to
  human review, which keeps the safety net. The threshold is currently 0.0,
  so every case counts as grounded.

**Evaluation.**
- Tune only on the dev split.
- Compare map against the new retrieval on the same cases that neither was
  tuned on: a new frozen sample, or the existing one used strictly for
  comparison.
- Report retrieval P@k, then precision, recall, F1, human-review rate and
  cost.
- Disclose which test set was used.

**Presentation.** Map (checkpoint) -> measured weaknesses -> semantic plus
expandable knowledge base -> measured gain. Present expandability as a
demonstrated property (unmapped CWEs are now handled), not as a claim that
TriageBot works for every CWE.
