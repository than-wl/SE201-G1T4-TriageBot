# TriageBot: Evidence-Grounded Multi-Agent Triage of Static Security Scanner Alerts

## 1. Team and Project Information
**Team:** [TEAM NAME]

- **Darren** — static-analysis integration, alert normalisation/routing, benchmark preprocessing
- **Wei Lin** — security-knowledge RAG and source-code context retrieval
- **Hong Yi** — multi-agent council and LLM orchestration
- **Lisa** — deterministic validation and human-review workflow
- **Bradley** — evaluation harness, baselines, metrics, and experimental analysis

## 2. Problem Statement
Static Application Security Testing (SAST) tools flag potentially vulnerable code, but some alerts are false positives that still require manual investigation. Developers and application-security teams must inspect surrounding code, data flow, helper functions, and configuration before deciding whether an alert is genuine. Reviewing every alert consumes engineering effort, while dismissing alerts too aggressively risks hiding real vulnerabilities.

**TriageBot** improves this existing software-engineering practice by acting as a post-processing layer after a conventional SAST scanner. It investigates each scanner finding and returns **likely real vulnerability, likely false positive, or human review required**, together with supporting evidence. It does not replace the scanner or attempt to discover vulnerabilities the scanner missed.

## 3. Justification for Using AI
The conventional approach is scanner rules followed by manual security review. Deterministic rules are effective when facts can be checked exactly, but contextual triage may depend on control flow, sanitisation, helper functions, or configuration spread across the codebase. An LLM can interpret source code and security guidance together, combine evidence from multiple locations, and explain its conclusion.

TriageBot grounds this reasoning using retrieved source-code context and OWASP security guidance. An **Analyst** builds the case that a finding is genuine, a **Skeptic** searches for counter-evidence and unsupported assumptions, and a **Chair** makes an evidence-based decision. A deterministic validator then checks claims that can be verified mechanically. We will test whether this council improves triage over a single LLM agent given the same evidence and tools, rather than assuming multi-agent reasoning is better.

## 4. Proposed Solution and Technical Approach
**[Insert the revised high-level architecture diagram here]**

Data flows from **source code → SAST scanner → alert normalisation → evidence retrieval → Analyst/Skeptic/Chair council → deterministic validator → triage outcome**. Source-code tools retrieve relevant files/functions, while RAG retrieves OWASP security guidance using CWE metadata and semantic similarity. The validator checks objective claims such as whether cited files, lines, methods, or simple code conditions exist; unsupported or uncertain decisions are sent to human review.

**Planned stack:** Python; Semgrep Community Edition for SAST; OpenRouter for hosted LLM access with a fixed instruction model (**planned primary model: Gemini 3.8 Flash; access to be confirmed by smoke test**); SentenceTransformers + FAISS for local retrieval; OWASP security guidance for RAG; and OWASP Benchmark Java v1.2 for evaluation.

## 5. Evaluation Plan
The **OWASP Benchmark Java v1.2** provides 2,740 labelled test cases and an official answer key, allowing automatic scoring. TriageBot will be evaluated only on alerts produced by the scanner because it is a triage layer, not a vulnerability-discovery system.

We will compare: **A)** scanner only, **B)** single LLM agent with the same evidence/tools, **C)** Analyst–Skeptic–Chair council, and **D)** council + deterministic validator. Primary metrics are **genuine findings retained, false-positive alerts removed, genuine vulnerabilities wrongly dismissed, human-review rate, and per-category performance**; latency/token use will also be recorded. Initial success means retaining **≥95% of genuine scanner findings** while removing **≥25% of false-positive alerts** without sending most cases to human review.

To reduce benchmark contamination, comments/hints will be removed from the LLM-facing evaluation copy while preserving scanner input and line mapping. Selected mutation tests will flip a small code condition and check whether the model's verdict changes accordingly. Failure cases and any lack of improvement from the council will be analysed.

## 6. Checkpoint Targets
By **18 October**, we will:
- run the selected scanner on the OWASP Benchmark, join findings to the answer key, and produce the baseline scorecard;
- connect the main pipeline from scanner alert through retrieval, LLM triage, validation, and report, with incomplete components clearly stubbed/documented;
- demonstrate at least one reasoning-heavy vulnerability category end-to-end with working retrieval and an initial Analyst–Skeptic–Chair workflow;
- evaluate about **100 scanner findings**, report initial metrics/failures, and maintain a shared repository with setup instructions, contributions from all members, and the required AI-use disclosure log.
