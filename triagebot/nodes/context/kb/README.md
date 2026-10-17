# Context knowledge base (`kb/`)

A committed, offline copy of security guidance used by the context-payload
node. At runtime the pipeline reads only these JSON files — it never
fetches web content (see design decision 2 in `doc/DESIGN_DECISIONS.md`).

## Provenance and licence

- **Source:** [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org),
  obtained from the site's official "Download Site" bundle (all 137 cheat
  sheets, HTML).
- **Copyright:** OWASP Foundation and the cheat-sheet contributors.
- **Licence:** CC BY-SA 4.0 — reuse here preserves attribution and
  share-alike; the canonical URL is embedded in every chunk so downstream
  citations always point back to the original page.
- The downloaded HTML bundle itself is **not** committed; only the derived
  chunk JSON is. Anyone can rebuild the identical KB from the public
  bundle with the command below.

## Layout

| Path | Purpose |
| --- | --- |
| `build_kb.py` | Local-only builder: HTML bundle -> chunks, indexes |
| `docs/<Sheet>.json` | One file per cheat sheet: title, URL, heading-based chunks |
| `cwe_map.json` | `CWE-xx` -> list of cheat-sheet docs covering it |
| `common.json` | Chunks included in every payload regardless of CWE |

## How chunks are produced

- **Heading-based sections:** one chunk per h2-h4 section, carrying its
  full heading path (e.g. `Primary Defenses > Defense Option 1: ...`).
  Oversized sections split at block boundaries; code samples stay intact
  as fenced blocks; tiny sections (bare reference lists) are dropped.
- **CWE map = mention detection + curated pins.** Cheat sheets rarely
  state their own CWE id in prose (the SQL-injection sheet never writes
  "CWE-89"), so `build_kb.py` pins the OWASP Benchmark's CWE categories to
  their dedicated prevention sheets and unions those with all incidental
  CWE mentions found in the text. Pinned names are validated against real
  filenames at build time.
- **`common.json` is the gate-miss fallback**, curated from the cheat
  sheets whose guidance is CWE-agnostic (secure code review, general
  injection rules, input validation principles). An alert with a
  mappable CWE receives chunks from its matched sheets alone; a gate
  miss receives these common chunks instead and sets
  `cwe_matched=false`, which routes the alert to human review.

## Rebuilding

1. Download the site bundle from `https://cheatsheetseries.owasp.org`
   ("Download Site" button) and extract it anywhere locally.
2. Run, from the repository root:

   ```powershell
   py -I triagebot/nodes/context/kb/build_kb.py --source <extracted>/site/cheatsheets
   ```

The build is stdlib-only, offline, and deterministic: the same bundle
always produces the same JSON. Commit the regenerated files together with
any `build_kb.py` change so the KB of record stays reproducible.

## Future upgrade (not the checkpoint mechanism)

Keyword ranking over these chunks is the checkpoint-stage retrieval
mechanism. If evaluation shows it is inadequate, the planned upgrade is
embedding-based retrieval (RAG) over the same committed chunk store —
the JSON layout is the stable interface, so the upgrade changes the
ranker, not the KB. See design decision 3 in `doc/DESIGN_DECISIONS.md`.
