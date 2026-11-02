# AI use disclosure

This document is the index for TriageBot's final AI-use evidence. It does not
replace the five members' detailed logs.

## Runtime AI in the product

The recorded evaluations used `google/gemini-3.8-flash` through OpenRouter at
temperature 0. TriageBot supplied each call with a Semgrep finding, bounded
source evidence and retrieved security guidance. The OWASP answer-key label was
kept outside all model prompts and used only by the evaluation harness after
predictions were complete.

The fresh 120-case run cost US$1.922363. Model output was treated as untrusted:
the pipeline constrained its structure, checked verdict/evidence consistency,
validated exact citations, and converted unsupported output to `human_review`.

## Development assistance by member

| Member | Detailed record | Main recorded contribution areas |
| --- | --- | --- |
| Bradley | [ai-log/bradley.md](ai-log/bradley.md) | Evaluation/scoring harness, mutation-style tests, checkpoint report draft |
| Darren | [ai-log/darren.md](ai-log/darren.md) | Ingest and Semgrep baseline, CLI/setup/CI, repository documentation |
| Hong Yi | [ai-log/hong-yi.md](ai-log/hong-yi.md) | Shared contracts, retrieval/context, review roles, LangGraph and SQLite sessions, semantic retrieval |
| Lisa | [ai-log/lisa.md](ai-log/lisa.md) | Deterministic schema/citation validation and disclosure documentation |
| Wei Lin | [ai-log/wei-lin.md](ai-log/wei-lin.md) | Integration, evaluations, measured architecture improvements, final reporting |

Each member remains responsible for reviewing and explaining submitted work.
The logs record significant tool use, checks performed, and what was kept or
changed. Git-history coverage notes were added on 2 November 2026 so that later
documentation-only work is not mistaken for missing implementation work.

## Known disclosure limitations

- A historical AI-assisted validator commit lacked the required `Assisted-by:`
  trailer. Lisa's log identifies it explicitly; shared history was not rewritten.
- A citation validator proves that quoted text exists. It does not prove the
  model's security interpretation is correct.
- Temperature 0 does not guarantee identical future output because the hosted
  provider and model can change.
- Raw paid-run outputs are excluded from the shared repository because they can
  contain source excerpts. The committed reports retain metrics, methodology,
  limitations and representative failures.

See [RESPONSIBLE_AI_RISK_ASSESSMENT.md](RESPONSIBLE_AI_RISK_ASSESSMENT.md) for
the complete risk register and human-oversight boundary.
