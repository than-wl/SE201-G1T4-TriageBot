# TriageBot Responsible-AI Risk Assessment

Status: final-project assessment. Update residual-risk statements if the final
experiment reveals a new failure mode.

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
- Reproducibility: model slug, prompts, scanner version, benchmark commit,
  split seed, selected case IDs, token use, cost, and latency are recorded.

## Risk register

| Risk | Potential harm | Mitigation in this prototype | Residual risk |
| --- | --- | --- | --- |
| Hallucination or unsupported reasoning | A genuine vulnerability could be dismissed, or a false alarm retained for invented reasons. | Exact file/line/quote citations are validated; malformed output and unsupported citations become `human_review`; council roles challenge the first analysis. | A plausible explanation can still misinterpret valid source lines. Human review remains necessary before suppression. |
| Prompt injection in source or scanner text | Adversarial comments or messages could tell the model to ignore its task or reveal data. | System prompts state that source and scanner text are untrusted data; the response is constrained to a strict JSON schema; only bounded source and curated OWASP guidance are supplied. | Instruction-following models may still be influenced by novel attacks. The prototype does not claim complete prompt-injection resistance. |
| Missed Semgrep finding | A vulnerability absent from stage-one output can never be recovered downstream. | Scanner recall is measured separately; `p/java` is compared with a higher-recall `p/java` plus `p/security-audit` configuration; whole-pipeline and conditional metrics are reported separately. | Semgrep remains a hard recall ceiling, and broader rules can add workload or unrelated findings. |
| Automation bias | Reviewers may trust a confident model verdict without checking evidence. | Verdicts include evidence, `human_review` is first-class, and documentation explicitly prohibits automatic production suppression. Success and failure examples are reported together. | Time pressure can still cause reviewers to over-trust the recommendation. |
| Privacy and confidentiality | Proprietary source code may be sent to an external provider. | Only a bounded source window and alert metadata are sent; secrets and the answer key are excluded; API keys stay in local environment files. | Even bounded code may be sensitive. A real deployment needs organisational approval, provider terms review, retention controls, and possibly a self-hosted model. |
| Security of credentials and logs | API keys or sensitive responses could leak through Git history or shared artifacts. | `.env` and raw runtime outputs are ignored; the key is never written to source; committed evidence contains summaries rather than credentials. | Local machines and external provider accounts remain attack surfaces. Keys require rotation and least privilege. |
| Dataset bias and representativeness | Strong OWASP Benchmark results may not transfer to real projects, languages, or coding styles. | Claims are limited to the pinned Java benchmark and selected CWE categories; per-category metrics and failure analysis expose uneven performance. | The benchmark is synthetic and cannot establish production accuracy or fairness across developer populations. |
| Benchmark memorisation or contamination | The model may recognise public benchmark patterns rather than perform general reasoning. | No answer labels are prompted; held-out cases are separated before final calls; mutation pairs test whether verdicts respond to changed code. | The public source may have appeared in training data, so held-out benchmark results are not equivalent to unseen real-world repositories. |
| Bias in risk prioritisation | Uneven accuracy across CWE categories could shift reviewer attention away from certain vulnerability classes. | The final sample is balanced within five categories and results are reported per CWE, not only as one aggregate. | Categories outside the sample and demographic or organisational effects are not evaluated. |
| Intellectual property and licensing | Sending or redistributing code or generated explanations could violate rights or licence terms. | Evaluation uses the public OWASP Benchmark and links to its provenance; no proprietary repository is used in the recorded experiment. | A deployment must confirm source-code and model-output licensing with the code owner and provider. |
| Cost and provider dependence | Unexpected token use, outage, model removal, or silent provider change could stop or alter triage. | Calls have bounded output tokens, no automatic retry after billing-uncertain failures, recorded model/provider metadata, and an explicit experiment budget. | Pricing, routing, and model behaviour remain external dependencies; a fallback provider would require revalidation. |
| Non-determinism | The same case may receive a different verdict later even at temperature 0. | A small fixed subset is repeated; raw verdict agreement, validation, model, latency, and cost are recorded. | Provider implementation changes and sampling can still alter results; exact reproducibility is not guaranteed. |

## Human oversight rule

For any real use, a qualified reviewer must inspect the cited code before a
finding is suppressed. TriageBot may rank or explain findings; it must not be
the sole authority for merging code, closing a security issue, or certifying a
system as secure.

## Claims we do not make

- TriageBot does not detect vulnerabilities that Semgrep missed.
- Benchmark performance does not establish real-world production accuracy.
- A validated citation proves that the quote exists, not that the model's
  security interpretation is correct.
- Temperature 0 does not guarantee deterministic output.
- The prototype is not a replacement for security engineers, penetration
  testing, dependency scanning, dynamic testing, or secure development review.
