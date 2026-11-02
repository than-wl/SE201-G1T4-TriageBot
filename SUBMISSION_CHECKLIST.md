# SE201 G1T4 final submission checklist

Last updated: 2 November 2026

Repository: <https://github.com/than-wl/SE201-G1T4-TriageBot>

Submission deadline: **10 November 2026, 12:00 Singapore time**, as one ZIP on
eLearn.

## Ready

- [x] Functional TriageBot prototype with documented setup and runnable commands
- [x] Repository source snapshot and public repository link
- [x] Latest architecture diagram with editable Mermaid source
- [x] Fresh 120-case evaluation with precision, recall, F1, cost, latency,
  per-CWE results, successes and failures
- [x] Controlled before/after architecture comparison
- [x] Responsible-AI risk assessment and human-oversight boundary
- [x] Consolidated AI-use disclosure plus all five individual member logs
- [x] Automated tests and cross-platform CI configuration
- [x] Secret-free package rules: no `.env`, API key, local benchmark checkout,
  raw paid outputs, virtual environment, cache, or local SQLite state

## Still required before upload

- [ ] Create and add the final presentation slides
- [ ] Ensure all five members can explain their work and answer questions
- [ ] Rehearse a presentation of at most 15 minutes, followed by 5 minutes Q&A
- [ ] Open the generated ZIP on a clean machine and follow its quick start
- [ ] Confirm the GitHub repository/branch referenced in the package is accessible
- [ ] Merge only after teammate review, then rebuild the package from the final
  reviewed commit
- [ ] Upload the final ZIP to eLearn before the deadline

## Highest-band review

Before submission, check that the slides and demonstration make these points
explicit:

1. The problem, why Semgrep alone is insufficient, and why an LLM council was
   chosen over the conventional single-agent alternative.
2. The prototype is functional and includes retrieval, multi-role review,
   consistency repair, deterministic citation validation and safe human review.
3. The datasets and metrics are justified, with both successful and failed
   cases discussed rather than only aggregate scores.
4. AI use, development assistance, risks, mitigations and residual limitations
   are disclosed comprehensively.
5. Every member's contribution is visible and each member is prepared to present.

## Package contents

The generated `dist/SE201_G1T4_TriageBot_Submission.zip` contains:

- `00_READ_ME_FIRST.md` with the repository link and final blocker;
- `TriageBot_Source.zip`, a clean Git snapshot of the reviewed branch;
- final results, responsible-AI assessment, AI-use disclosure and member logs;
- architecture diagram source and rendered GitHub Markdown;
- checkpoint report, experiment log and proposal PDF as supporting evidence.

The package intentionally excludes local `Context/` materials and generated raw
model outputs. Those remain local evidence and are not needed to run the project
from the committed recorded Semgrep scan.
