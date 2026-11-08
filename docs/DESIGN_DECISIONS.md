# TriageBot — Design Decisions

The team records its key design choices here so reviewers can see the
reasoning behind the checkpoint architecture. Each entry states the
decision, the alternative considered, and what the choice implies.
Status: living document, updated as the team decides.

## 1. Orchestration: council-only LangGraph after the checkpoint

**Historical checkpoint decision.** Plain Python functions and a two-way
`ThreadPoolExecutor` fan-out were sufficient for the recorded checkpoint.
That checkpoint implementation and its measured results remain historical evidence.

**Current Phase 1 decision (audited locally; reaches main with Phase 2).** Migrate only the
Analyst/Skeptic/Chair council to LangGraph, with explicit state in `state.py`
and the graph in `council_graph.py`. Keep the single-agent baseline as plain
Python and preserve the public `triage()` / `run_sample()` contracts.

**Why.** Establish explicit state and node boundaries for the agreed next
phase: durable SQLite checkpoints, followed later by a real human-review
handoff. This refactor is infrastructure work, not evidence of higher accuracy.
Parallel specialist independence and the single Chair join are unchanged.

**Consequence.** State contains JSON-compatible evidence and reports; callers,
KB objects, credentials and monotonic timing live outside it. LangGraph nodes
wrap existing review functions. No retry policy, persistence, HITL, tools,
retrieval change, or new safety gate is introduced in Phase 1. Phase 2 must
explicitly design cross-process timing and runtime-context reconstruction.
See `IMPLEMENTATION_HANDOVER.md` for the phased audit gates.

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

**Why.** The only consumers of prompt text are the four review roles, so
prompt text stays inside the review node and is not one of the shared
contracts at `triagebot/`'s top level (`schemas.py`, `config.py`), which a
reader can scan to see the dependency structure at a glance.

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


## 20. Opt-in SQLite checkpoints for council sessions (Phase 2)

**Decision (implemented; audited and reviewed in PR #13).** Add dedicated
`council-start`, `council-status` and `council-resume` commands backed by
`langgraph-checkpoint-sqlite==3.1.2`. Keep ordinary triage/evaluation and the
single-agent baseline unchanged. Store each run under a fresh UUID in a local
file-backed database; do not deploy DynamoDB or another hosted service.

**Why.** Recover council state across process restarts and prepare the foundation
for later HITL without implementing human pauses or a review document now.

**Consequences.**

- Checkpointer connections are scoped/closed, with supported cross-thread SQLite
  access for graph writes. One OS-level executor lock per DB prevents simultaneous
  continuations from charging for the same session; no distributed-service claim.
- Store a provenance manifest and compare source, corpus, model, settings, product
  code, package versions and Python minor before executing unfinished sessions.
  Runtime objects/keys remain outside state; fresh KB caches are loaded per run.
  Unknown fields (including answer-key labels) are rejected in persisted alerts.
- Resume uses input=None for the SAME thread. Completed runs are read without
  execution; incomplete recovery needs explicit --allow-replay. No automatic
  retry is added; crash-time billing is inherently uncertain and cost metadata
  only covers committed reports, not every possible provider charge.
- Persist per-role active durations, not a monotonic timestamp from another
  process. Durable latency is max(specialist durations)+Chair duration. Original
  ephemeral latency remains unchanged; disclose the metric difference.
- Recheck original source identity before validation; no source-to-sink analysis,
  no new verdict policy/CWE gate, no agent tools, and no human resolution are added.
- The database is sensitive local history, git-ignored and unencrypted. Trust the
  local DB; no external tracing is enabled. Avoid source/config/corpus changes
  while a run is active. Version migrations and production service hardening are
  future work, not part of this local prototype.

See README.md for operational commands and the EXISTING implementation handover
for the Phase 2 audit checkpoint. Recorded course-checkpoint scores stay unchanged.


## 21. Semantic guidance retrieval from the official CWE text (optional mode)

**Decision (implemented; default still "map").** `RETRIEVAL_MODE` in `config.py`
selects the ranker. "map" keeps the curated CWE-to-sheet gate. "semantic" takes the
scanner's CWE, looks up its record in the official MITRE CWE catalogue (pinned by
SHA-256, fetched once into the git-ignored `Context/tmp/cwe/`), embeds the record's
name and description with the local `bge-small-en-v1.5` model (fastembed, ONNX, no
server), and ranks every cheat-sheet chunk by cosine similarity. The chunks and their
vectors live in one SQLite file, `Context/tmp/kb_vectors.sqlite` (a BLOB per vector).
`sync()` embeds only chunks that are new or changed, so adding a document later is
chunk-and-sync. Search is exact numpy cosine; an index can be added later without a
data migration.

**Why.** The hand-written map covered 33 CWEs, and its links were our judgement.
The scan's 1,909 findings fall into only 9 CWEs, and 475 of them (CWE-326, 328, 501)
are outside the map. The MITRE text is authoritative and the lookup is deterministic.

**Grounding rule (applies to both modes).** A case is grounded only when the CWE is
present, known to the catalogue and not deprecated, and at least one chunk clears
`SEMANTIC_MIN_SCORE` (map mode: the CWE is in the map). An ungrounded case is never
given an automatic verdict: the validator sets `human_review` with a validation error,
whatever the model said. Before this change the validator did not read `cwe_matched`,
although the schema and decision 3 described it as doing so; that gap is now closed.

**Measurement (dev split only, CWE-89, 100 alerts, the fixed primary-sheet proxy).**
Map: 0/100 alerts with a primary SQL sheet in the guidance. MITRE text as the query:
100/100, with a primary-sheet share of 0.50. MITRE text plus the alert message: 0/100,
the same pull toward the general injection sheet that hybrid BM25 showed. The
threshold is not set. Every alert of one CWE shares one query, so its top score is
identical across those alerts, and the scores of correct and wrong sheets overlap
(CWE-326's wrong top sheet scores 0.741, CWE-328's correct sheet 0.735). Reading the
top six for each of the 9 scan CWEs found the right sheet for CWE-79, 328 and 643,
the right sheet only fourth for CWE-326, and no path-traversal sheet in the KB for
CWE-22. Semantic retrieval cannot supply guidance the knowledge base does not contain.

**Graded relevance study (all 9 scan CWEs).** The proxy above rests on a document-name
guess, and the map was itself generated without verification. So the candidates (the
union of the top dense and top BM25 results for each CWE, 130 chunks) were graded by
reading their text: 2 = guidance about this weakness, 1 = adjacent, 0 = not relevant.
The grades are one reader's judgement and have not been independently reviewed; they are
in `verification/relevance_labels.json`, and `verification/relevance_eval.py` reproduces
the table. Precision@2 / @6 (grade 2 only), macro over the 9 CWEs:

| Method | P@2 | P@6 |
| --- | ---: | ---: |
| Dense, MITRE text as the query | 0.61 | 0.54 |
| BM25 | 0.33 | 0.37 |
| Dense + BM25, equal weight | 0.61 | 0.46 |
| Dense + BM25, 0.7 / 0.3 | 0.56 | 0.57 |
| Reranker MiniLM-L-6 (cross-encoder) | 0.33 | 0.44 |
| Reranker bge-reranker-base | 0.44 | 0.43 |

The curated map scores P@2 0.58 on the 6 CWEs it covers, against 0.67 for dense on the
same 6, and 0.39 against 0.61 over all 9, because it has no entry for CWE-326, 328 and
501. On this evidence dense is at least as good as the map where both answer and the only
one that answers elsewhere; adding BM25 or an off-the-shelf reranker does not help.
CWE-79 and CWE-501 score 0 for every method: for CWE-501 the KB holds no code-level
guidance, and for CWE-79 the relevant chunks are present but ranked low. Nine CWEs and one
reader make this a direction, not a verdict.

**Consequences.**
- The default remains "map"; switching to "semantic" is one config line and needs
  the team's review of the measurement above. The test half of the split is untouched.
- Map mode now routes CWE-326, 328 and 501 to human review (475 of 1,909 findings),
  where the previous code sent them to the model. This is the rule as specified, and it
  will change any aggregate that counts human-review cases.
- Ungrounded cases still spend model calls before the validator overrides them. Skipping
  those calls is a possible saving, not implemented.
- The catalogue is not committed (its licence terms are not yet checked). The SQLite
  store is derived from the committed KB and is git-ignored; it is not part of the
  Phase 2 KB fingerprint, which hashes the JSON source files.
- The committed KB repeats 22 chunks verbatim. The semantic store keeps one row per
  chunk_id; the map path still reads the raw JSON, so its results do not change. The
  duplicates should be removed at source by the KB builder, which is a data change to
  review separately.


## 22. Reconciling PR #14 (evaluation improvements) with the LangGraph council

**Decision.** PR #14 was built on the pipeline before the council moved to LangGraph.
Merging it onto `main` as is would have kept its source-context and validation changes
but silently dropped its consistency-repair step from council mode, because the graph
never called it. The repair step is therefore a graph node of its own
(`chair -> repair -> validate`), and the shared logic lives in `triagebot/execution.py`
so the plain-Python single-agent path and the graph run the same code.

- **One repair call at most.** If the Chair's verdict contradicts its structured
  analysis, one repair call is made; a repair that is still inconsistent becomes
  `human_review`. No automatic retry beyond that. With a consistent verdict the node
  makes no model call.
- **Its own node,** so a crash after the Chair does not repeat the paid Chair call
  (Phase 2). The durable latency adds the repair duration:
  `max(analyst, skeptic) + chair + repair`. The checkpoint schema version is now 2, and
  the provenance guard also covers the related-source limits and the retrieval settings.
- **Validation context.** `validation_case` carries the quoted related files as
  `source_files`, so a citation into a helper is checked against that helper's text.
- **Source window.** This branch keeps PR #14's 60 lines together with its related-file
  context, because its 66-case comparison was measured that way. Decision 19's 100 lines
  had only a smoke test behind it. The two have not been compared on the same cases,
  so this is provisional and one config line.

**Limitations.**
- Durable runs fingerprint only the alert's own source file. The related files chosen
  during `build_context` are not fingerprinted, so a change to a helper between
  creation and resume is not caught.
- PR #14's reported numbers were produced before the graph. They are not claimed for the
  graph path until the comparison is re-run there.


## 23. Frozen evaluation case sets and a retired-case list

**Decision.** Every new result is measured on one of three frozen case sets in
`data/samples/`, built by `python -m triagebot.nodes.ingest.eval_sets build`
from the recorded scan, the answer key and the fixed split (decision 18):

- `pilot` (development half): exactly the 100-case checkpoint sample; the
  builder stops if it differs from `evidence/checkpoint-100/`. With the other
  unused development cases it forms the **exploration set**, where failures
  are read and ideas tried.
- `comparison` (development half): CWE-22, 78, 79 and 89, 24 cases each, half
  real and half safe, no pilot case. Frozen; only measured, never tuned on.
- `final-test` (test half): the same four CWEs, 30 cases each, half real and
  half safe, run once after the code freeze.

`data/samples/retired_cases.json` lists the 407 cases used by any earlier run
(every `selected_alerts.json` under `evidence/` plus the fresh-120 audit list,
which adds the OpenRouter smoke-test case). The final test must share no case
with it; the builder asserts this, and asserts the same for the comparison set.

**Why.** We train no model, but we tune by hand: we read the cases TriageBot
gets wrong and change it. A change made after reading a case tends to fix that
case, so a set that was read cannot also measure the change. Earlier runs mixed
the two and changed several things at once. Fixing the sets in advance, with
fingerprints, makes every later step comparable with every other.

**Consequence.** Sample files hold only NormalisedAlert fields (decision 7);
the manifests hold the rule, seed, scan and sample SHA-256 and per-CWE counts,
never a per-case label. Fingerprints are taken over LF line endings and
`.gitattributes` keeps the files LF, so they match on Windows and macOS.
Building twice gives byte-identical files. The final test leaves 15 safe
command-injection cases eligible for 15 places, so the test half has no spare
CWE-78 safe case after this set.

## 24. Experiment profiles and the one-change-per-step rule

**Decision.** `triagebot/profiles.py` defines four named profiles, `base`,
`evidence`, `worksheet` and `semantic`, each a value for the same four switches:
source window (25 or 60 lines), related source (on or off), reasoning worksheet
with consistency repair (on or off), and guidance retrieval (`map` or
`semantic`). `use_profile(name)` applies one for the length of a run and
restores the previous settings afterwards, even on failure. Each experiment step
(`EXPERIMENTS.md`, `experiments/registry.json`) moves from one profile to the
next, so exactly one group of settings changes, and is measured on the same
frozen comparison set.

**Why.** A before/after difference can only be attributed to a change if
nothing else changed. Naming the groups makes that checkable: each run manifest
records the profile and every setting it applied.

**Consequence.**

- The switches are read at call time: `SOURCE_RELATED_ENABLED` in
  `source_context.py`, `REVIEW_WORKSHEET_ENABLED` in `prompts.report_contract()`,
  `openrouter.report_schema()` and `execution.repair_if_inconsistent()`, and
  `RETRIEVAL_MODE` when a `KnowledgeBase` is created. With the worksheet off the
  `analysis` object is neither asked for nor allowed by the strict schema, and
  the repair never fires. The config defaults equal the `worksheet` profile, so
  commands run outside an experiment behave as before, and with the worksheet on
  the prompts and schema are byte-identical to the previous ones.
- Engineering fixes are not switched: strict JSON schema output, guidance-label
  normalisation in the validator and the LangGraph council stay on everywhere.
- A `semantic` run stops before any call, naming the command to run, while the
  MITRE catalogue or the vector store is missing.
- The durable council sessions (decision 20) add the profile name and settings
  to their provenance, so a session started under one profile cannot be resumed
  under another.
- Every run is resumable (one JSON line per finished case), replayable for free
  (`experiment replay` re-scores the saved outputs and checks they match the
  saved evaluation) and shown for free (`experiment show`, offline, no key).

## 25. The per-type checklists are removed

**Decision.** The short trusted checklists the prompt added for CWE-78 and
CWE-90 (`_CWE_CHECKLISTS` and `for_cwe()` in `prompts.py`) are removed for good,
in every profile. Every weakness now gets the same system prompt.

**Why.** Both were written after reading specific cases the council had got
wrong (the CWE-78 environment-array cases and the LDAP helper flows). That tunes
the prompt to the cases it is measured on, which is what the case split
(decision 23) exists to prevent. Hand-written notes per weakness also do not
scale beyond the Benchmark's categories.

**Consequence.** Results recorded with the checklists (the 66-case runs from the
improvement change of 29 October onwards, and the fresh 120) are not reproducible
with the current code; they are archived evidence (decision 23). The tests that expected the checklists now
check that no checklist reaches any prompt. Weakness-specific guidance, if
needed, must come from the retrieved OWASP material.

## 26. The step 4 rule for semantic retrieval, agreed in advance

**Decision.** Step 4 compares semantic retrieval (decision 21) with the curated
map on the comparison set. If semantic retrieval holds or improves accuracy, it
is reported as an improvement. If not, it remains the design choice, argued on
scalability and maintainability, and the slide states the accuracy difference
plainly. Any tuning of its set-up happens on exploration cases only, followed by
one measurement on the comparison set.

**Why.** Semantic retrieval is preferred for reasons accuracy does not capture:
it needs no hand-made table and covers any CWE the MITRE catalogue knows. Fixing
the reporting rule before the run prevents choosing the story after seeing the
numbers, and prevents tuning on the comparison set until it looks good.

**Consequence.** The step 4 result is reported whichever way it falls. A second
measurement on the comparison set after tuning would break this rule; the
comparison set is measured once per configuration.

## 27. The reasoning worksheet is dropped from the final version

**Decision.** The `semantic` profile, and so the final version, runs without the
reasoning worksheet and its consistency repair. Step 4 builds on step 2 (the
`evidence` profile) and changes only the guidance retrieval.

**Why.** On the 96-case comparison set (EXPERIMENTS.md, steps 3 and 1c) the
worksheet changed nothing beyond the noise floor for the council (sent to a
human 4 to 3), and the single agent dismissed more real vulnerabilities with it
(3 to 5). It worked as designed: all 96 answers filled every field and every
verdict agreed with its worksheet, so the repair call never fired. The problem
it targeted, a verdict that contradicts the model's own reasoning, appeared in
earlier runs with a ±25-line window and did not occur once the AI saw enough
code. Keeping it would add about 8% to cost and a second prompt shape for no
measured gain.

**Consequence.** The `worksheet` profile and its runs stay, so step 3 remains
replayable. The worksheet code stays behind its switch (`REVIEW_WORKSHEET_ENABLED`)
and can be turned back on if a later evaluation shows a need. The config default
is now off (`REVIEW_WORKSHEET_ENABLED = False`), so a normal run matches the final
version; only the `worksheet` profile turns it on, and every profile sets it.

## 28. The semantic retrieval set-up is fixed before step 4 is measured

**Decision.** Before step 4 is run, semantic retrieval (decision 21) gets five
rules, each a switch in `config.py`. All five off is decision 21's set-up
exactly; the `semantic` profile turns all five on.

- **R1 Query** (`SEMANTIC_QUERY_ALT_TERMS`): the query adds MITRE's
  `Alternate_Terms`: "{Name}. Also known as: {terms}. {Description}".
- **R2 MITRE text** (`SEMANTIC_MITRE_GUIDANCE`, cap 1,500 characters): the
  CWE's MITRE description, extended description and mitigations (each with
  its phase) become the first guidance chunk, `MITRE-CWE-<id>`. It is looked
  up by CWE ID, never embedded or searched. Examples and CVE lists are left out.
- **R3 Sheets searched** (`SEMANTIC_KB_SCOPE`, `KB_TARGET_PLATFORM = "java"`):
  `kb/scope.json`, written from each sheet's title and opening paragraph,
  leaves out retired sheets, the attack-string catalogue and sheets for other
  platforms (21 of 137).
- **R4 Chunk size** (`SEMANTIC_MAX_CHUNK_CHARS = 1800`): longer chunks are
  split at load time at blank lines, then line breaks, then sentence ends
  (214 chunks into 447 pieces). The KB JSON is unchanged.
- **R5 Grounding** (`SEMANTIC_GROUNDING = "mitre_record"`): an alert is
  grounded if and only if its CWE has a valid, non-deprecated MITRE record.

**Why.**

- *Categories, not a hand-made list.* The team's investigation of decision 21's
  set-up found that retired sheets, attack strings and sheets for Django,
  Laravel, .NET and others could outrank guidance that applies to Java. The
  rules name categories and are applied to every sheet from its title and
  opening, never from retrieval results, so they cannot be tuned to the
  results we like.
- *A platform switch keeps the system general.* Sheets about one language or
  framework are tagged, not deleted. Scanning a Python repository means
  setting `KB_TARGET_PLATFORM = "python"`, not writing a new list.
- *MITRE is attached by ID, not found by search.* A query built from a CWE's
  own description would mostly find its own record, so searching for it would
  look better than it is. Lookup by ID is deterministic and gives every known
  CWE authoritative guidance, including CWEs the OWASP sheets do not cover.
- *The grounding gate checks a fact, not a score.* At 0.0 the old threshold let
  everything through, and decision 21 showed that cosine scores of right and
  wrong sheets overlap, so no threshold separates them. Whether a valid MITRE
  record exists is a fact. `SEMANTIC_MIN_SCORE` stays at 0.0 and is used only
  by the original gate.
- *The budget is unchanged.* Step 4 is compared with `2-after`, so the pack
  stays at 4,000 characters and 6 chunks; the MITRE chunk counts against both.
- *Splitting oversized chunks.* The embedding model reads only about the first
  512 tokens, so the rest of a long chunk was never searched, and one chunk
  could fill the whole budget.

**Consequence.**

- The default `RETRIEVAL_MODE` stayed `"map"` until step 4 was measured; since
  then semantic retrieval with these five rules on is the default (decision 29).
  Map retrieval, `cwe_map.json` and the KB JSON files are unchanged, and map mode
  ignores the new switches.
- The vector store holds every chunk plus the split pieces, so `python -m
  triagebot.nodes.context.vector_store` prepares both set-ups and switching
  between them re-embeds nothing. The pieces have new IDs (`<chunk_id>.1`, …);
  chunks within the cap keep theirs, so their grades in
  `verification/relevance_labels.json` stay valid.
- Semantic run manifests record the five settings and the SHA-256 of
  `scope.json`; a run cannot be resumed with a different set-up.
- `python -m triagebot.nodes.context.retrieval --explain CWE-89 [--setup
  original|improved]` shows how one CWE's pack is built, without model calls.
- MITRE text is now quoted in prompts, so MITRE's copyright line and terms of
  use are reproduced in `triagebot/nodes/context/MITRE_CWE_NOTICE.md` and
  linked from the README and `kb/README.md`. In semantic mode the prompt's
  guidance block is labelled "Retrieved guidance (MITRE CWE and OWASP Cheat
  Sheet Series)"; map-mode prompts are byte-identical (a test pins them).
- Two limits are kept on purpose, so step 4 differs from `2-after` in
  retrieval only: filling the budget stops at the first chunk that does not
  fit, and the MITRE chunk's 1,500-character cap can cut later mitigations
  (EXPERIMENTS.md, step 4, "Known limits").
- These rules were set without looking at any comparison-set or final-test
  case. Any further change to the set-up follows decision 26: exploration
  cases only, then one measurement.

## 29. Semantic retrieval is the default

**Decision.** Semantic retrieval with the improved set-up (decision 28, rules R1
to R5 on) is the default and the final version. In `config.py`,
`RETRIEVAL_MODE = "semantic"`, and the five set-up switches default to the
values the `semantic` profile uses and step 4 measured:
`SEMANTIC_QUERY_ALT_TERMS = True`, `SEMANTIC_MITRE_GUIDANCE = True`,
`SEMANTIC_KB_SCOPE = True` with `KB_TARGET_PLATFORM = "java"`,
`SEMANTIC_MAX_CHUNK_CHARS = 1800` and `SEMANTIC_GROUNDING = "mitre_record"`.
Changing only the mode would have made the default decision 21's original
set-up, which is not what was measured. Step 6 runs this version on the final
test.

**Why.** Step 4 held accuracy within the noise floor (council F1 96.0% → 95.0%,
one case of 96; EXPERIMENTS.md, step 4), which by the rule agreed in advance
(decision 26) counts as holding. It also covers any CWE MITRE knows without a
hand-written row: for 10 weaknesses outside the benchmark the right sheet
reached the guidance in all 10, and 5 of them have no row in the hand-made
table.

**Consequence.**

- Anyone running TriageBot needs two one-time prepare steps, local and with no
  model calls: `python -m triagebot.nodes.context.cwe_catalogue` (the MITRE
  catalogue, SHA-256 pinned) and `python -m triagebot.nodes.context.vector_store`
  (downloads the embedding model and builds the local vector store). They are in
  the README quick start. A normal run (`triage`, `evaluate`, `council-start`,
  `council-resume`, menu options 2 and 3) stops before any model call, naming
  both, while either is missing; before this change a missing vector store was
  built silently on first use.
- The map remains available as `RETRIEVAL_MODE = "map"` and in the profiles of
  steps 1 to 3 (`base`, `evidence`, `worksheet`), which set it explicitly. Every
  profile sets every setting that matters, so the new defaults change no profile,
  and replaying steps 1 to 4 gives identical results.
- The original set-up stays reproducible: `--explain --setup original`,
  `verification/semantic_setup_check.py` and the regression test for "all five
  rules off" set `profiles.SEMANTIC_SETUPS["original"]` explicitly and never rely
  on the config defaults. Offline tests that relied on the map being the default
  now set it, and no test loads the embedding model or needs the catalogue.
- This replaces the default named in decisions 21 ("default still map") and 24
  ("the config defaults equal the `worksheet` profile"), which describe the
  state before step 4. The worksheet default is off as well (decision 27), so
  every setting the `semantic` profile sets equals its config default; a test
  keeps a normal run and the final version from drifting apart.

## 30. The mutation test is rebuilt

**Decision.** Step 5 ("Does the verdict follow the code?") is rebuilt on a
frozen mutation set, `data/samples/mutation.json`, built by a deterministic
script (`python -m triagebot.nodes.ingest.eval_sets mutation`). Each pair is a
Benchmark case whose answer is decided by one constant condition,
`(<int> * <int>) <+|-> num > 200 ? "<string>" : <identifier>`, and its mutant,
which swaps `>` for `<` in that expression and changes nothing else. A case
counts only if it is a development case outside the pilot, comparison and
retired lists, of type CWE-22, 78, 79 or 89 with a CWE-matching alert, holds
exactly one such ternary and one `int num = <int>;`, passes the flip proof
(evaluated with its own constants, the condition flips and is not tied at 200),
and its label matches the branch. Three pairs per direction per type are drawn
with seed 201; two strata have only two eligible cases, so the set has 22
pairs, not 24. Both sides run the final version (the `semantic` profile),
single agent and council, on one commit. The mutants run from overlay roots
and are scored against the flipped answers. The result is a mutation score per
configuration and direction. The old `verification/mutation_check.py` is kept
as a record and marked superseded.

**Why.** The old test could not show whether verdicts follow the code. Its
baselines differed between reviewers (the council's "original" results came
from a script version without council mode). It ran each case from a folder
holding only the mutated file, so mutants lost the related source the
`evidence` profile reads. And it used five hand-picked cases, all in one
direction (safe to vulnerable). Here, the eligibility rule is written down and
applied by code, so the cases are not chosen by hand, and both directions are
measured. Keeping only cases whose label matches the branch means flipping the
branch really flips the right answer. The overlay root (a copy of
`src/main/java` and `src/main/resources` with only the mutated file replaced)
gives a mutant exactly the evidence its original gets: a test checks that the
two evidence packs differ only on the mutated line. A pair counts only when the
original was judged right, so a mutant "flip" is not credited to a reviewer
that was already wrong. An escalation is reported apart, because sending a
case to a human is not following the code.

**Consequence.**

- `mutation.json` holds no labels. The evaluation side computes the expected
  answers: the original's from the answer key, and the mutant's as its flip.
  Only development-half source files are read, after the split filter, so no
  final-test case is opened.
- `experiment run 5` builds the overlay roots under
  `Context/tmp/mutation-overlay/` (git-ignored, about 18 MB per case) before
  any model call. The Benchmark checkout is only read: files are copied, never
  linked. Each case's record holds the SHA-256 of the file it was judged on.
- Both sides run on one commit: the run refuses uncommitted changes to tracked
  files, and a commit other than the one a saved step 5 run recorded.
- Comments never reach the AI (`strip_comments`); on the 22 real pairs, no text
  that exists only in a comment reached a prompt. String literals are code and
  stay: a real-to-safe mutant uses the constant `"This should never happen"`,
  a cue that points the wrong way. This is a property of the Benchmark and is
  reported, not removed.
- The cost is 176 calls, about US$0.83 (the per-case costs of step 6), for 22
  pairs.
- **Also fixed: tests never touch the real vector store.** On 8 Nov the
  checkpoint tests synced `Context/tmp/kb_vectors.sqlite` with their one-chunk
  fixture knowledge base (`SQL#1`), leaving 1 row. Once semantic retrieval
  became the default (decision 29), `KnowledgeBase(<fixture folder>)` with no
  embedder used the real store, and `checkpoints._fresh_kb` dropped the
  caller's mode on resume. Three changes stop it happening again. The real
  store is now used only for the committed knowledge base; any other folder
  gets an in-memory store unless a path is given. Every test module imports
  `tests/isolated_store.py`, which points `config.KB_VECTOR_DB` at a temporary
  file. And `VectorStore.sync()` refuses a sync that would delete more than
  half of the stored rows unless `allow_large_delete=True`, which only the
  prepare command passes.
