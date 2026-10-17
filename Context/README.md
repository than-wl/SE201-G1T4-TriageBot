# Context/ (local-only workspace)

This folder is each member's local workspace. Only this note and `.gitignore` are tracked;
shared project documents live under `docs/`.

- `tmp/` is the local data folder used by the scripts and instructions: the OWASP Benchmark
  checkout (`tmp/BenchmarkJava`), Semgrep output, raw model responses and run artefacts.
  It is git-ignored because it is large, third-party, or contains the answer key and
  unreviewed model output.
- Restricted SMU course PDFs (project brief, lecture slides) stay here locally; obtain them
  through eLearn and never commit them.
- Never commit `.env`. The OpenRouter key belongs only in the root `.env` file.

Benchmark setup instructions are in the root `README.md` (Setup).
