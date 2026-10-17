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
mentions, because cheat sheets rarely state their own CWE id in prose),
then keyword ranking orders the candidate chunks — matched documents plus
a small always-included set of CWE-agnostic chunks — using terms derived
from the alert (rule id, message, source/sink APIs), and the top few
chunks become the payload's guidance. An alert with no mappable CWE
receives only the always-included chunks and is flagged
`cwe_matched=false`, which the validator routes to human review.

Keyword ranking is the deliberately simplified checkpoint mechanism
inside an otherwise complete retrieval component; the architecture
component itself (payload-node retrieval with a defined input, output,
and committed KB) is built and connected, and the brief permits
documented simplifications of component internals.

**Why.** The CWE field already exists in the normalised alert, so
retrieval needs no additional coupling to ingest. Keyword ranking is
deterministic and dependency-free, making results reproducible and the
KB easy to extend with new documentation files rather than code changes.
The always-included set guarantees agents receive general review guidance
even when the CWE gate misses.

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
