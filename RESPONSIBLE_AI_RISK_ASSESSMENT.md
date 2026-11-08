# TriageBot Responsible-AI Risk Assessment

Status: final-project assessment, updated 9 November 2026 after the experiments
in [EXPERIMENTS.md](EXPERIMENTS.md) (steps 1 to 6). The figures below come from
there.

## Intended use and boundary

TriageBot is a decision-support prototype for prioritising Semgrep findings. It
does not prove that code is secure and must not automatically suppress a
finding in production. A `human_review` verdict means the evidence is
insufficient; invalid or missing model output is also converted to
`human_review`. Findings that Semgrep never raises cannot be recovered by the
LLM stage.

## AI-use disclosure

- Runtime AI: OpenRouter chat completions using
  `google/gemini-3.8-flash`, temperature 0, for the single-agent and
  Analyst/Skeptic/Chair configurations.
- Development AI: team members record material AI assistance in `ai-log/` and
  remain responsible for reviewing, testing, and explaining submitted work.
- Evaluation labels: the OWASP Benchmark answer key is used only after model
  calls for stratified sampling and scoring. It is never included in prompts.
- Reproducibility: every experiment run records its profile and settings, the
  case set and its fingerprint, the model, temperature, Git commit, token use,
  cost and latency (`evidence/experiments/<run>/run_manifest.json`). The saved
  verdicts are committed, and `python -m triagebot experiment replay <step>`
  re-scores them for free.

## Risk register

| Risk | Potential harm | Mitigation in this prototype | Residual risk |
| --- | --- | --- | --- |
| Hallucination or unsupported reasoning | A genuine vulnerability could be dismissed, or a false alarm retained for invented reasons. | Exact file/line/quote citations are validated; malformed output and unsupported citations become `human_review`; the Skeptic challenges the Analyst and the Chair weighs both reports. On the final test the council dismissed 1 of 60 real vulnerabilities (the single agent 10). | A plausible explanation can still misread valid source lines: in step 4 all three reviewers dismissed a real path traversal (`BenchmarkTest01983`) with a plausible but incomplete argument. Human review remains necessary before suppression. |
| Prompt injection in source or scanner text | Adversarial comments or messages could tell the model to ignore its task or reveal data. | System prompts state that source and scanner text are untrusted data; the response is constrained to a strict JSON schema; only bounded source and retrieved MITRE CWE and OWASP guidance are supplied. | Instruction-following models may still be influenced by novel attacks. The prototype does not claim complete prompt-injection resistance. |
| Missed Semgrep finding | A vulnerability absent from stage-one output can never be recovered downstream. | Scanner recall is measured separately, and the whole system is projected against Semgrep alone. For the four measured types Semgrep's recall is 86.0% and the whole system's 85.0%; of about 117 real vulnerabilities the whole system misses, 109 are ones Semgrep never flagged. A broader `p/java` plus `p/security-audit` scan raises Semgrep's recall over all 2,740 cases (CWE-matched 68.6% → 86.5%) only by adding weak randomness and insecure cookie findings; for the four measured types it is unchanged. | Semgrep remains a hard recall ceiling and is now the bottleneck. Broader rules can add workload and help only the categories they cover. |
| Automation bias | Reviewers may trust a confident model verdict without checking evidence. | Verdicts include evidence, `human_review` is first-class, and documentation explicitly prohibits automatic production suppression. Success and failure examples are reported together. | Time pressure can still cause reviewers to over-trust the recommendation. |
| Privacy and confidentiality | Proprietary source code may be sent to an external provider. | Only bounded source evidence is sent: ±60 lines around the alert, the methods it calls, referenced project files and scripts, and retrieved guidance. Secrets and answer-key labels are excluded; API keys stay in local environment files. | Even bounded related files may be sensitive. A real deployment needs organisational approval, provider terms review, retention controls, and possibly a self-hosted model. |
| Security of credentials and logs | API keys or sensitive responses could leak through Git history or shared artifacts. | `.env` and local runtime outputs are ignored; the key is never written to source; committed evidence holds verdicts, reports and short excerpts from the public benchmark, never credentials. | Local machines and external provider accounts remain attack surfaces. Keys require rotation and least privilege. |
| Dataset bias and representativeness | Strong OWASP Benchmark results may not transfer to real projects, languages, or coding styles. | Claims are limited to the pinned Java benchmark and four CWE categories; per-category metrics and failure analysis expose uneven performance. | The benchmark is synthetic and cannot establish production accuracy or fairness across developer populations. |
| Benchmark memorisation or contamination | The model may recognise public benchmark patterns rather than perform general reasoning. | No answer labels are prompted; tuning cases and reported cases are kept apart, and the final test was run once on 120 unseen cases. The mutation test (step 5) changes one character so that the right answer flips while the alert stays the same: the council flipped correctly in 22 of 22 pairs, the single agent in 8 of the 15 it got right to begin with. | The public source may have appeared in training data, so held-out benchmark results are not equivalent to unseen real-world repositories. 22 pairs of one pattern show the council usually follows the code, not that it always does. |
| Bias in risk prioritisation | Uneven accuracy across CWE categories could shift reviewer attention away from certain vulnerability classes. | The final test is balanced across four CWE categories (30 each, half real) and results are reported per CWE: the council's F1 was 96.8% (path traversal), 90.3% (OS command injection), 100% (XSS) and 100% (SQL injection). | Categories outside the sample and demographic or organisational effects are not evaluated. |
| Missing or weak guidance coverage | Weak or wrong guidance could mislead the review, and a CWE with no guidance could not be judged. | Guidance comes from semantic search over the OWASP cheat sheets, anchored on the alert's MITRE CWE record, which is attached first. Any CWE with a valid MITRE record gets guidance with no hand-written entry; an unknown or deprecated CWE goes to human review. For 10 weaknesses outside the benchmark, the right sheet reached the guidance in all 10. | The knowledge base has no path-traversal sheet, so for CWE-22 the MITRE record is the only guidance about path traversal itself. The relevance grades behind the retrieval check are AI-produced and unreviewed. |
| Intellectual property and licensing | Sending or redistributing code or generated explanations could violate rights or licence terms. | Evaluation uses the public OWASP Benchmark and links to its provenance; no proprietary repository is used. The OWASP cheat sheets (CC BY-SA 4.0) and MITRE CWE text are used under their terms, reproduced in the repository. | A deployment must confirm source-code and model-output licensing with the code owner and provider. |
| Cost and provider dependence | Unexpected token use, outage, model removal, or silent provider change could stop or alter triage. | Calls have bounded output tokens, no automatic retry after billing-uncertain failures, and recorded model/provider metadata. Each paid run prints its estimated cost and asks first; the final test refuses a second run. | Pricing, routing, and model behaviour remain external dependencies; a fallback provider would require revalidation. |
| Non-determinism | The same case may receive a different verdict later even at temperature 0. | The base council was run twice with identical settings on 96 cases; the runs differed on 1 case. Differences of 2 or more cases are treated as more than noise. | Provider implementation changes and sampling can still alter results; exact reproducibility is not guaranteed. |

## Human oversight rule

For any real use, a qualified reviewer must inspect the cited code before a
finding is suppressed. TriageBot may rank or explain findings; it must not be
the sole authority for merging code, closing a security issue, or certifying a
system as secure.

## Evidence from the final test (step 6)

The final test used 120 cases nobody had read or tuned on: 60 real and 60 safe,
30 per type across path traversal, OS command injection, XSS and SQL injection.
It was run once, after the code freeze. The council, after the deterministic
validator, reached 95.2% precision, 98.3% recall and 96.7% F1; it removed 57 of
60 false alarms, dismissed 1 of 60 real vulnerabilities, and sent 1 case to a
human. The single agent removed the same 57 but dismissed 10. Projected over
the whole benchmark for the four types, Semgrep plus the council would cut
false alarms from 453 to about 20 (precision 59.6% → 97.1%) while recall falls
from 86.0% to 85.0%. These results support feasibility on this benchmark, not
autonomous production use.

## Claims we do not make

- TriageBot does not detect vulnerabilities that Semgrep missed.
- Benchmark performance does not establish real-world production accuracy.
- A validated citation proves that the quote exists, not that the model's
  security interpretation is correct.
- Temperature 0 does not guarantee deterministic output.
- The prototype is not a replacement for security engineers, penetration
  testing, dependency scanning, dynamic testing, or secure development review.
