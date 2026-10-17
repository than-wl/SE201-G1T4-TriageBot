# Shared Project Context

This folder contains the small set of project-owned documents that teammates need while implementing the checkpoint.

## Files shared through Git

- `G1T4 Proposal.pdf` - the submitted proposal and the canonical project commitments.
- `FEASIBILITY_CHECK_REPORT.md` - results from the five-case council feasibility test.
- `OPENROUTER_SMOKE_REPORT.md` - results from the five-case OpenRouter smoke test.
- `TriageBot_Proposal_two_page_draft.md` - an older editable draft for reference only; the submitted PDF is canonical.

## Files intentionally not shared through Git

- The official SE201 project brief and lecture PDFs are SMU course materials. Team members should obtain them through eLearn.
- `tmp/` contains generated evidence, raw model responses, a downloaded Semgrep wheel, rendered PDF pages, and a nested third-party OWASP Benchmark repository. It is intentionally local.
- `Codex Handoff.md` is a stale local working note, not a project requirement or team instruction.
- `.env` remains local because it contains credentials.

## OWASP Benchmark setup

The benchmark is not copied into this repository. Clone the official repository into the ignored local path:

```powershell
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git Context/tmp/BenchmarkJava
git -C Context/tmp/BenchmarkJava checkout 8b67a88d73b2594570fc21150705283de884620b
```

The pinned commit is the version used for the existing feasibility evidence. Do not send the official answer-key labels to the LLM. The answer key is used only by the evaluation code after model calls are complete.

## Secrets

Never commit an OpenRouter key. Put it only in the local root `.env` file. Repository access does not grant OpenRouter access.
