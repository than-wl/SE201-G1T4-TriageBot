# AI Use Log: Darren

Entries follow the SE201 AI Use Disclosure Policy v1.00: one entry per
significant use, committed with the work it describes.

## 2026-10-18 — Repository documentation grooming

- **Tool (model):** Claude Code (claude-opus-5-5)
- **Files:** README.md, Context/README.md, CHECKPOINT_REPORT.md (path fixes only),
  checkpoint/CHECKPOINT_BRADLEY.md, checkpoint/CHECKPOINT_BRIEF.md,
  checkpoint/CHECKPOINT_DARREN.md, checkpoint/CHECKPOINT_TEAM_TASKS.md,
  checkpoint/Checkpoint_WEILIN_FINAL_INTEGRATION_AND_SUBMISSION.md,
  docs/DESIGN_DECISIONS.md (moved from doc/), docs/proposal/G1T4_Proposal.pdf (moved),
  docs/feasibility/FEASIBILITY_CHECK_REPORT.md (moved, path fix),
  docs/feasibility/OPENROUTER_SMOKE_REPORT.md (moved),
  Context/TriageBot_Proposal_two_page_draft.md (deleted),
  docs/architecture/TriageBot_Architecture_Diagram.drawio.svg,
  docs/architecture/TriageBot_Architecture_Diagram.png, ai-log/darren.md
- **Outcome:** Changed

### What I asked for

Reorganise the repository's documentation: rename `doc/` to `docs/`, move the
shared proposal and feasibility reports out of `Context/` into `docs/`, and fix
every reference to the moved files. Rewrite the README as one coherent document
covering the pipeline stages and their status, setup, running, team roles, AI
disclosure and safety rules, without changing any Python behaviour or tests.

### How I checked it

- Reviewed the staged diff.
- Ran the offline tests: all 46 still pass.
- Had Claude Code search for stale references to moved files.
- Reviewed the rewritten README in Cowork.


### What I kept or changed

- Kept the structure and README as written.
- Left two old `doc/` references in teammates' AI logs unchanged, since they record what was true at the time.
