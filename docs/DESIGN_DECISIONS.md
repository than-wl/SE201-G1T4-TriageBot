# TriageBot — Design Decisions

The team records its key design choices here so reviewers can see the
reasoning behind the checkpoint architecture. Each entry states the
decision, the alternative considered, and what the choice implies.
Status: living document, updated as the team decides.

## 1. Orchestration: plain Python for the checkpoint

**Decision.** The checkpoint pipeline is plain Python: stages are ordinary
functions wired by `triagebot/pipeline.py`. We adopt LangGraph only if
functionality is required that plain Python cannot provide cleanly
(branching, retries, or stateful loops).

**Why.** The current topology is a straight sequence with one two-way
parallel stage, which `concurrent.futures` covers directly. Adding a
framework would introduce a dependency and setup cost for every member
without changing capability at this stage.

**Consequence.** Nodes carry no framework dependency, so a later switch to
LangGraph would be contained in `pipeline.py` alone. The team re-evaluates
if the pipeline grows real conditional flows.

## 2. Guidance is fetched at payload-build time, not by the agents

**Decision.** Security guidance is retrieved by our code while building the
context payload. Agents do not receive web-search or browsing tools.

**Why.** The model must receive guidance as data inside the prompt anyway;
fetching at build time keeps retrieval deterministic, auditable, and free
of runtime network access from the model loop. Tool-calling agents remain
a candidate future feature, not part of the checkpoint scope.

**Consequence.** Every payload's guidance can be reproduced from the KB
version, and prompt-injection surface through live web content is avoided.

## 3. Guidance retrieval: CWE-keyed local KB with keyword ranking

**Decision.** The KB is a committed, offline corpus of the OWASP Cheat
Sheet Series, chunked by section and indexed by CWE. Retrieval works in
two stages: a CWE gate selects the documents mapped to the alert's CWE
(via a build-time map of curated category pins unioned with detected
mentions, because cheat sheets rarely state their own CWE id in prose).
On a gate hit, keyword ranking orders the matched documents' chunks by
terms derived from the alert (rule id, message, source/sink APIs) and
the top-ranked chunks within a fixed budget become the payload's
guidance. On a gate miss, a small curated set of CWE-agnostic review
chunks is sent instead and the payload is flagged `cwe_matched=false`,
which the validator routes to human review.

Keyword ranking is the deliberately simplified checkpoint mechanism
inside an otherwise complete retrieval component; the architecture
component itself (payload-node retrieval with a defined input, output,
and committed KB) is built and connected, and the brief permits
documented simplifications of component internals.

**Why.** The CWE field already exists in the normalised alert, so
retrieval needs no additional coupling to ingest. Keyword ranking is
deterministic and dependency-free, making results reproducible and the
KB easy to extend with new documentation files rather than code changes.
The curated fallback guarantees agents still receive general review
guidance on a gate miss, without spending prompt budget on general
material when specific guidance exists.

**Consequence.** Adding a vulnerability category later means adding files
to `triagebot/nodes/context/kb/`. The expected upgrade for the final
system is embedding-based retrieval (vector similarity search, i.e. RAG)
over the same committed chunk store, motivated if evaluation shows the
keyword ranker misses relevant guidance; the chunk JSON layout is the
stable interface, so that upgrade replaces the ranker, not the KB.

## 4. Council: concurrent specialists, single join

**Decision.** The council is a two-way fan-out: Analyst and Skeptic both
receive the same context payload, run concurrently, and do not see each
other's output. Only Chair depends on prior results and joins both reports.

**Why.** Independence keeps the two perspectives from anchoring on each
other, which is the point of the multi-agent design in the proposal. It
also halves wall-clock latency versus sequential roles.

**Consequence.** The council costs three model calls per case and Chair's
input is the only dependency edge; specialist prompts are tested
individually.

## 5. Review strategies share one interface

**Decision.** The single-agent baseline and the council are interchangeable
review strategies: same input type, same output type, selected by
configuration.

**Why.** The proposal commits to comparing a single agent against the
council on identical evidence. Making them swappable keeps that comparison
fair by construction — the only difference between conditions is which
reviewer runs.

**Consequence.** The evaluation harness compares conditions without code
changes, and a third strategy can be added later without touching the
pipeline.

## 6. Model selection is configuration, not code

**Decision.** The model slug is read from configuration
(`OPENROUTER_MODEL`), with a low-cost model for development runs and the
proposal's model (`google/gemini-3.8-flash`) for recorded final runs. Every
run records the exact model, token usage, latency, and cost.

**Why.** Recorded results must stay comparable with the proposal and
earlier feasibility evidence, while day-to-day iteration should stay cheap.

**Consequence.** No source edits are needed to switch models, and every
result table can state exactly which model produced it.

## 7. The answer key is isolated to evaluation

**Decision.** Ground truth from the OWASP answer key is read only by the
evaluation node (`triagebot/nodes/score/`), never by ingest, payload
construction, prompts, or saved request payloads.

**Why.** The evaluation must measure what the system does without the
labels, otherwise results are meaningless. This was a stated commitment in
the proposal.

**Consequence.** A test asserts that no answer-key field ever appears in a
prompt payload.

## 8. Validation is deterministic code, separate from the model

**Decision.** Post-review checks (JSON shape, citation file/line/quote
verified against actual source) are pure code in
`triagebot/nodes/validate/`, independent of any model or agent role.
Unverifiable output falls back to `human_review` with reasons.

**Why.** The model's output cannot be trusted to be internally consistent;
a check that itself uses an LLM would inherit the same failure modes.
Deterministic checks are offline-testable and reproducible.

**Consequence.** Fabricated citations are rejected mechanically, and the
validator can be exercised in tests with no API key.

## 9. Repository layout: product code, planning docs, and feasibility history

**Decision.** Product code lives in `triagebot/` (one folder per pipeline
node), team planning documents in `checkpoint/`, and the original
feasibility scripts remain untouched in `verification/` as historical
evidence of the feasibility stage.

**Why.** The product structure is organised around the final architecture,
so components can grow into their folders instead of being rewritten; the
feasibility scripts record what was verified before the checkpoint and
should not be retro-edited.

**Consequence.** New development happens in `triagebot/`;
`verification/` scripts continue to run as the recorded feasibility tests
until their logic is superseded by pipeline components.

## 10. Offline-first development via injectable callers

**Decision.** Review nodes receive a caller object instead of building HTTP
requests themselves; live (OpenRouter) and offline (fixture) callers
implement the same interface.

**Why.** All component tests must run without network access or API spend,
which the checkpoint requires (offline tests for every component) and
which lets any member work on a clean clone with no key.

**Consequence.** The Definition of Done for the AI workflow is provable
without paid calls; live runs are limited to integration checks and the
recorded final evaluation.

## 11. The caller owns model-JSON parsing and never retries

**Decision.** Each review role passes a request dict
(`system`, `user`, `max_tokens`, `temperature`) to an injected caller;
the caller adds the model/endpoint/auth, parses the model's JSON answer
into a dict, and returns `{"_error": reason}` on any transport, auth, or
billing failure instead of raising. Roles never auto-retry.

**Why.** Keeping parsing in one place means every role sees the same
shape and a malformed answer cannot crash a run mid-pipeline. The
team's workflow rule is no automatic retries, so the failure path must
degrade safely rather than propagate exceptions.

**Consequence.** A failed call becomes a `human_review` report via the
shared report helper (decision 13), and swapping live/fixture callers
requires no role changes (decision 10).

## 12. Review prompts live inside the review node

**Decision.** All prompt text — role system prompts, the shared output
contract, and the evidence-block renderer — lives in
`triagebot/nodes/review/prompts.py`, not at the package top level.

**Why.** The only consumers of prompt text are the four review roles;
`triagebot/`'s top level stays limited to the contracts every module
depends on (`schemas.py`, `config.py`), so a reader can see the
dependency structure at a glance.

**Consequence.** Prompt edits are reviewed inside the review node's
pull requests, and prompt-text review (a future evaluation activity)
has one file to audit.

## 13. All strategies see one byte-identical evidence block

**Decision.** The context payload is rendered by a single function into
one evidence block that is embedded verbatim as the user message for
every role and both strategies. Extracted facts appear as labelled
hints to verify, and the block is framed as untrusted data that carries
no instructions.

**Why.** The proposal's core comparison (single agent vs council) is
only meaningful if the evidence is identical by construction, not by
convention. Facts must not become verdict logic — the model has to
verify them against the code. Framing the block as data also bounds
prompt injection through source comments or retrieved guidance.

**Consequence.** Fairness is mechanically testable (byte-equality of
user messages across strategies), the smoke test asserts it, and the
untrusted-data framing complements the deterministic validator.

## 14. Model reports are normalised in one shared helper

**Decision.** Every role routes its parsed model dict through
`triagebot/nodes/review/report.py`: identity fields (`role`, `case_id`)
are stamped by code and never read from the model, unknown or missing
verdicts coerce to `human_review`, list fields are shape-guarded, and a
caller failure (decision 11) becomes a safe `human_review` report.

**Why.** The model cannot be trusted to declare its own identity or to
respect the verdict enum; all four roles must emit one shape for the
validator; and failure handling should be written once, not four times.

**Consequence.** Adding a fifth role means a prompt plus a thin wrapper;
the validator (decision 8) stays the sole enforcer of evidence rules —
the helper only normalises shape.

## 15. Guidance citations are a separate additive field

**Decision.** Agent reports carry `guidance: [{chunk_id, doc, section,
url}]` next to the contractual `citations`. Guidance refs are copied
only from the retrieved chunks listed in the evidence block; `citations`
stays source-code evidence with the team document's exact shape.

**Why.** Downstream reporting and evaluation benefit from knowing which
cheat-sheet chunks a verdict actually relied on, while the team
document's `citations` contract must not change under the validator
author's feet.

**Consequence.** The validator gains one additive rule (every guidance
ref must match a listed chunk), and result files record code evidence
and documentation evidence separately.

**Implemented.** `validator.py` accepts `guidance` as an optional field: each
ref must be exactly {chunk_id, doc, section, url} and match a caller-supplied
`guidance_chunks` entry on all four; refs without supplied chunks fail, and an
empty or missing list passes.

## 16. AI assistance is disclosed per the SE201 policy

**Decision.** Every commit containing AI-assisted work carries an
`Assisted-by: <tool> (<model>)` trailer (the Linux/LLVM convention the
policy adopts), and each team member keeps `ai-log/<member>.md` with one
entry per significant use — tool, files, outcome (Kept/Changed/Rejected)
plus what was asked, how it was checked, and what was kept or changed —
committed with the work it describes.

**Why.** The course's AI Use Disclosure Policy v1.00 requires both parts
and treats undisclosed use as an academic integrity breach; committing
entries with the work links log entry, diff, and trailer in one history.

**Consequence.** PR review includes the log entry for the work; the
checkpoint submission includes the `ai-log/` folder to date and a short
team declaration (policy section 5.1) in the checkpoint document.

## 17. Scanner baseline uses CWE-matched scoring

**Decision.** In the scanner-only baseline, a Benchmark case counts as
flagged only if one of its alerts carries the case's Benchmark CWE or a
documented equivalent. Filename matching (any alert on the case's file
counts as flagged) is still computed and reported next to it, for
comparison with the proposal's preliminary figures.

**Why.** Filename matching credits Semgrep for an alert that names a
different weakness than the one the test case contains, such as an XSS
rule firing on a trust-boundary test. Matching on CWE measures whether
the scanner found the weakness the answer key describes. Some rules tag
a neighbouring CWE for the same code pattern, so an exact-match rule
alone would understate the scanner.

**Consequence.** The equivalence table is data-driven: it lives in
`triagebot/nodes/ingest/mapping.py` (`ACCEPTED_CWE_EQUIVALENTS`), and
each entry, accepted or rejected, is decided from the mismatch report
that ingest prints and records with its reason. The table currently
accepts only CWE-326 for CWE-327 (Semgrep's DES/DESede rules).
`baseline.json` records both modes and the table used.

## 18. Fixed, stratified dev/test split

**Decision.** The 2,740 Benchmark cases are split once into dev and test
halves (seed 201, 50/50), stratified by category and answer-key label.
Prompts, retrieval and other settings are tuned on dev cases only; the
checkpoint sample is drawn from dev. The test split is reserved for the
final evaluation.

**Why.** Instructor feedback asked that the system be evaluated on data
it was not tuned on. A fixed seed makes the split reproducible by every
member, and stratifying keeps each category's share of real and false
alerts the same in both halves.

**Consequence.** `split.json` records the seed, fraction, per-stratum
counts and full assignment. Changing the seed or fraction would
invalidate the separation between tuning and final results, so it needs
a team decision recorded here.

## 19. Source window widened from ±25 to ±100 lines

**Decision.** The context payload slices comment-stripped source around
each alert at `config.SOURCE_WINDOW_LINES`. After the recorded
checkpoint run, the window was raised from 25 to 100 lines (on
`checkpoint/hong-yi-source-window`).

**Why.** In the recorded run, most human-review escalations traced to
helper methods cut off mid-body by the ±25 slice: the Chair could not
see the branch connecting user input to the sink (BenchmarkTest01004,
BenchmarkTest01883). The same slice also bounds `extract_facts`, so the
fact hints were starved together with the code. 100 lines keeps whole
helper methods for typical Benchmark test files; the extra input is one
source window per call, still small against the model budget.

**Consequence.** The recorded checkpoint numbers (produced at ±25)
stand unchanged; any comparison run must fix one window and state
which. The slice is still a hard bound — files wider than the window
remain truncated, so a full re-run must re-check for any such cases.
