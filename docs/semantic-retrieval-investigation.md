# Semantic guidance retrieval: investigation notes (8 Nov 2026)

Status: investigation only. No pipeline code was changed, no paid model calls were made,
the held-out test split and the answer key were not touched. Default `RETRIEVAL_MODE`
remains `"map"`, so every recorded result in `evidence/` is unaffected.

Audience: an engineer or coding agent deciding whether and how to improve the optional
semantic retrieval mode (design decision 21, PR #15). Read `docs/DESIGN_DECISIONS.md` §21
first; this note extends it.

## 1. Question

All recorded evaluations ran with the curated CWE→cheat-sheet map
(`triagebot/nodes/context/kb/cwe_map.json`, 33 keys). The semantic mode is implemented,
merged and measured for retrieval quality, but never used end to end. Was it left off
because the approach is weak, or because of how it was built and fed?

Short answer: the approach is sound; the query construction and the corpus held it back,
and one genuine blocker remains (no usable confidence signal for the grounding gate).

## 2. How semantic mode works today

- `KnowledgeBase._retrieve_semantic` (`triagebot/nodes/context/retrieval.py`, ~L123-142):
  normalise the alert's CWE → look up the MITRE record → query =
  `CweCatalogue.query_text(entry)` = `"{Name}. {Description}"`, capped at
  `SEMANTIC_QUERY_MAX_CHARS = 1000` → cosine against every KB chunk → keep chunks with
  score `>= SEMANTIC_MIN_SCORE` → `_within_budget` (top 6, 4000 chars) →
  `cwe_matched = bool(chunks)`.
- `cwe_catalogue.load_entries` (`triagebot/nodes/context/cwe_catalogue.py`, ~L60-68)
  parses only `Name` and `Description` per `Weakness`. Everything else in the record
  is discarded.
- Embedding: `BAAI/bge-small-en-v1.5` via fastembed, with the BGE query prefix;
  chunk text = `section + "\n" + text` (`embeddings.chunk_text`).
- Config (`triagebot/config.py`): `RETRIEVAL_MODE = "map"`,
  `SEMANTIC_MIN_SCORE = 0.0` (commented as a placeholder).
- Validator: `guidance_matched is False` → `UNGROUNDED_ERROR` → `human_review`.
  With threshold 0.0, every known CWE is "grounded" in semantic mode, so turning the
  mode on would silently disable the gate.

Important property: the query depends only on the CWE, not on the alert or the code.
Every alert of a CWE gets the same chunks and the same top score. Semantic mode is
therefore an automatically derived CWE→chunks map, not per-alert retrieval. Any
threshold acts per CWE, not per alert.

## 3. Why it was never switched on (from PR #15 and DD21)

- PR #15 (merged 31 Oct 2026) has zero reviews and zero comments. The PR body states:
  "Independent review of the grades and of the retrieval code is still pending" and
  "The similarity threshold is a placeholder (0.0), because the data could not support
  a value."
- The 130 relevance grades in `verification/relevance_labels.json` were produced by the
  AI assistant, not by a team member (PR body, AI usage table).
- No end-to-end verdict evaluation was run in semantic mode. The headline fresh-120 run
  (2 Nov) used map mode.
- The same PR made the validator honour `cwe_matched`. In map mode this sends all of
  CWE-326, 328 and 501 (475 of 1,909 scan findings) to human review. On fresh-120 the
  council was 12/12 correct on CWE-501, and all 12 were overridden.

So it was not rejected on evidence. It was merged two days before the final run, never
reviewed, and could not be enabled safely without a threshold.

## 4. Findings

### 4.1 Query construction discards the most useful MITRE fields

The pinned catalogue (CWE 5.0) has, per weakness: `Alternate_Terms`,
`Extended_Description`, `Potential_Mitigations`, `Demonstrative_Examples`,
`Technical_Nuance` and more. The query uses only `Name` + `Description`, and MITRE 5.0
names omit the common name:

| CWE | Query starts with | Alternate_Terms in the record (unused) |
|---|---|---|
| 79 | "Improper Neutralization of Input During Web Page Generation." | Cross-site Scripting, XSS, HTML Injection, Reflected/Stored/DOM-Based XSS |
| 89 | "Improper Neutralization of Special Elements used in an SQL Command." | SQL Injection, SQLi |
| 22 | "Improper Limitation of a Pathname to a Restricted Directory." | Path traversal, Directory traversal |
| 78 | "Improper Neutralization of Special Elements used in an OS Command." | Shell injection, OS Command Injection |

The cheat sheets are titled and written with the common names.

### 4.2 The CWE-501 gap is in the KB, not in the available data

DD21 records CWE-501 as 0 for every method because the KB has no code-level guidance.
That is true of the OWASP KB. However, the MITRE CWE-501 record already downloaded
contains a `Demonstrative_Example` of exactly the Benchmark pattern:

```
usrname = request.getParameter("usrname");
if (session.getAttribute(ATTR_USR) == null) { session.setAttribute(ATTR_USR, usrname); }
```

The Benchmark CWE-501 cases do the same, e.g. `BenchmarkTest00010`:
`request.getSession().putValue("userid", param);`. The record is used only as a query and
never offered as guidance.

### 4.3 Corpus quality

`kb/docs/` holds all 137 OWASP cheat sheets (3,238 chunks, 22 more in `common.json`).
Problems for a Java/servlet target:

- Four sheets are deprecation stubs with one chunk each:
  - `Injection_Prevention_in_Java_Cheat_Sheet`: "This information has been moved to the dedicated Java Security CheatSheet"
  - `Access_Control_Cheat_Sheet`
  - `Transport_Layer_Protection_Cheat_Sheet`
  - `TLS_Cipher_String_Cheat_Sheet`
- `XSS_Filter_Evasion_Cheat_Sheet` (105 chunks of attack payloads) is the top CWE-79
  result under the current query (0.83).
- Many sheets are for other stacks or domains: Laravel, Symfony, Django, DotNet, Rails,
  PHP, Node, Next.js, Kubernetes, Docker, Drone, Automotive, AI advertising, AML
  payments and others. For CWE-22 the only grade-2 "path traversal" chunks are in
  Laravel and Symfony (PHP). There is no Java path-traversal guidance in the KB.
- 23 chunks exceed 2,000 chars (max 11,744). bge-small truncates input at 512 tokens, so
  their vectors represent only the opening portion.
- The KB does contain usable crypto guidance (Cryptographic_Storage, Password_Storage,
  Key_Management). The map simply has no entry for CWE-326, 327, 328 or 330.

### 4.4 Similarity scores do not separate right from wrong

Top-6 scores fall in 0.68-0.87 across all CWEs. Correct and incorrect chunks sit within
about 0.01-0.05 of each other. Examples:
- CWE-326: the wrong top chunk (Browser_Extension) scores 0.74, the correct
  Web_Service_Security chunk 0.74.
- CWE-501: unrelated Secure_Cloud_Architecture chunks score 0.77.

A raw cosine threshold cannot implement the grounding gate. This is the genuine blocker,
and it explains the 0.0 placeholder.

### 4.5 Measurement correction

The concern that DD21's P@2 = 0.61 was inflated because `relevance_eval.py` ranks only
within the labelled candidate pool was checked and is not supported. Full-corpus
retrieval with the current query also gives macro P@2 = 0.61 (0 unlabelled chunks in the
top 2).

## 5. Experiment

Setup:
- Full-corpus dense retrieval, the same model and prefix as production, top-2.
- Precision counts grade-2 chunks from `verification/relevance_labels.json`. Unlabelled
  chunks count as not relevant, so new variants are penalised, not flattered.
- "Alert-weighted" weights each CWE by its finding count in the recorded scan: 79:456,
  89:388, 326:301, 22:288, 78:221, 328:113, 501:61, 90:54, 643:27; total 1,909.

Variants:
- **Query:** current (Name + Description), or +alt (insert
  `"Also known as: <Alternate_Terms>."` after the name).
- **Corpus:** full, or filtered. The filter drops other-stack, cloud/infra, AI-domain,
  deprecated-stub and attack-payload sheets, leaving 2,116 of 3,238 chunks. It is a
  regex denylist; see Appendix A.

| Setup | macro P@2 | alert-weighted P@2 | CWEs with both top-2 relevant | ≥1 of top-2 relevant | unlabelled in top-2 |
|---|---:|---:|---:|---:|---:|
| A full KB, current query (as built) | 0.61 | 0.47 | 4/9 | 7/9 | 0/18 |
| B full KB, +alt | 0.61 | 0.45 | 5/9 | 6/9 | 2/18 |
| C filtered KB, current query | 0.61 | 0.52 | 4/9 | 7/9 | 1/18 |
| D filtered KB, +alt | **0.67** | **0.64** | 5/9 | 7/9 | 1/18 |

Per CWE (P@2), A → D:

| CWE | A | D |
|---|---:|---:|
| 79 | 0.0 | 1.0 |
| 89 | 0.5 | 0.5 |
| 326 | 0.5 | 0.5 |
| 22 | 0.5 | 0.0 |
| 78 | 1.0 | 1.0 |
| 328 | 1.0 | 1.0 |
| 501 | 0.0 | 0.0 |
| 90 | 1.0 | 1.0 |
| 643 | 1.0 | 1.0 |

The CWE-22 drop comes from removing the PHP sheets. Whether PHP guidance counts as
relevant for Java code is debatable.

Top results for CWE-79 under D: Java_Security (2), DOM_based_XSS_Prevention (2),
Cross_Site_Scripting_Prevention (unlabelled, very likely 2). Under A:
XSS_Filter_Evasion (0), Input_Validation (1).

Interpretation:
- Neither change helps alone. Together they give a modest macro gain (+0.06) and a
  meaningful volume-weighted gain (+0.17), almost entirely from CWE-79.
- A trial with Potential_Mitigations appended to the query was mixed: macro 0.44 with
  5/18 unlabelled, inconclusive. Mitigation text looks more useful as guidance content
  than as query text.

Limitations of this experiment:
- 9 CWEs.
- Labels are AI-produced and unreviewed.
- The corpus filter was hand-picked after looking at results, so D is optimistic.
- Retrieval quality only: no verdict-level evaluation.

## 6. Recommended changes (priority order)

All of these live in semantic mode, which is off by default, so recorded results stay
valid. Do not change the default before an end-to-end evaluation on the dev split.

1. **Query: add Alternate_Terms.** In `cwe_catalogue.load_entries`, parse
   `Alternate_Terms/Alternate_Term/Term`, store it as `alt`, and make `query_text` return
   `"{name}. Also known as: {alt}. {description}"`. Add a unit test with a fixture
   record.
2. **Corpus scoping for the semantic index.**
   - Drop the four deprecation stubs at source in `build_kb.py`. Also dedupe the 22
     repeated chunks noted in DD21.
   - Add sheet metadata (platform/language, kind = prevention | attack | process) at
     build time, and let the semantic index filter by the target stack (Java/servlet).
   - Exclude attack-payload sheets (`XSS_Filter_Evasion`) from guidance.
   - Prefer a declared allowlist over the ad-hoc denylist used here.
3. **MITRE content as guidance.** Chunk `Extended_Description`, `Potential_Mitigations`
   and `Demonstrative_Examples` into KB documents, with source = MITRE CWE and
   per-record URL `https://cwe.mitre.org/data/definitions/<id>.html`. This closes the
   CWE-501 gap with authoritative text, and gives CWE-326 and 328 code-level guidance.
   **First check the CWE terms of use and record the attribution;** DD21 notes that
   the licence is "not yet checked". Keep the catalogue itself out of git, as now.
4. **Re-chunk oversized chunks** to ≤ ~1,800 chars so the 512-token embedding window
   covers them.
5. **Replace the raw-cosine gate.** Candidates, to evaluate on dev:
   - (a) margin or agreement: top-k chunks concentrated in one sheet, or top score
     minus the median of the top 50 above a cut-off;
   - (b) a per-CWE "validated" flag set from human-graded dev relevance (honest about
     being a learned map);
   - (c) an LLM relevance check on the retrieved chunks (costs calls; must not see the
     answer key);
   - (d) a stronger embedding model or a domain reranker. Off-the-shelf MiniLM and
     bge-reranker did not help in DD21.

   Report the gate's precision and recall against the graded labels.
6. **Have a team member review the labels independently** and grade the new candidates
   surfaced by the variants. Report agreement.
7. **End-to-end evaluation, dev split first:**
   - Compare map and improved semantic retrieval on verdict metrics, especially
     CWE-326, 328 and 501, which map mode always escalates.
   - Only then consider a fresh unseen test sample.
   - Paid OpenRouter runs need explicit confirmation from the team. The budget
     discussed was ≤ US$2.

## 7. Constraints

- Never commit `.env`, keys, the Benchmark checkout, raw paid outputs, course PDFs, or
  anything under `Context/` except its README and `.gitignore`.
- The answer key (`expectedresults-1.2.csv`) must never enter a prompt or retrieval.
- Do not tune on the held-out fresh-120 sample; it has been inspected.
- Keep `RETRIEVAL_MODE = "map"` as the default unless an end-to-end dev evaluation
  supports switching. Record any change as a new design decision.

## Appendix A: reproduction (free, local, no API calls)

```bash
python -m venv .venv-sem && .venv-sem/Scripts/python -m pip install fastembed==0.9.1 python-dotenv rich==15.0.0
.venv-sem/Scripts/python -m triagebot.nodes.context.cwe_catalogue   # fetch + SHA-256 verify CWE 5.0 into Context/tmp/cwe/
.venv-sem/Scripts/python verification/relevance_eval.py             # DD21 table (candidate-pool ranking)
.venv-sem/Scripts/python semantic_probe.py                          # the script below (full-corpus)
```

The first run embeds all chunks on CPU into `Context/tmp/kb_vectors.sqlite`, which is
git-ignored. This took over 10 minutes on a laptop; later runs reuse it.

```python
"""Full-corpus semantic retrieval probe: query variants x corpus filter."""
import json, re, sys, xml.etree.ElementTree as ET
from pathlib import Path
ROOT = Path(".").resolve(); sys.path.insert(0, str(ROOT))
from triagebot import config
from triagebot.nodes.context.embeddings import FastEmbedder
from triagebot.nodes.context.retrieval import KnowledgeBase
from triagebot.nodes.context.vector_store import VectorStore

W = {"CWE-79": 456, "CWE-89": 388, "CWE-326": 301, "CWE-22": 288, "CWE-78": 221,
     "CWE-328": 113, "CWE-501": 61, "CWE-90": 54, "CWE-643": 27}
DROP = re.compile(r"Laravel|Symfony|Django|DotNet|Ruby_on_Rails|PHP|Nodejs|NodeJS|NPM|FastAPI|"
    r"Nextjs|JavaScript_and|Browser_Extension|Mobile_App|Drone|Automotive|Kubernetes|Docker|"
    r"Advertising|AML_|XSS_Filter_Evasion|Access_Control_Cheat|Transport_Layer_Protection|"
    r"TLS_Cipher|Injection_Prevention_in_Java|Secure_Cloud|Microservices|Serverless|"
    r"Infrastructure_as|GitHub_Actions|CI_CD|Zero_Trust|Multi_Tenant|LLM_|RAG_|AI_Agent|MCP_|"
    r"Secure_AI|Secure_Coding_with_AI")
loc = lambda e: e.tag.split("}")[-1]
txt = lambda e: " ".join(" ".join(e.itertext()).split())

rec = {}
for w in ET.parse(config.CWE_CATALOGUE_XML).getroot().iter():
    key = f"CWE-{w.get('ID')}"
    if loc(w) == "Weakness" and key in W:
        d = {"name": w.get("Name"), "desc": "", "alt": []}
        for c in w:
            if loc(c) == "Description": d["desc"] = txt(c)
            if loc(c) == "Alternate_Terms": d["alt"] = [txt(t[0]) for t in c if len(t)]
        rec[key] = d

def query(cwe, with_alt):
    d = rec[cwe]
    alt = f" Also known as: {', '.join(d['alt'])}." if with_alt and d["alt"] else ""
    return f"{d['name']}.{alt} {d['desc']}"[: config.SEMANTIC_QUERY_MAX_CHARS]

kb, emb = KnowledgeBase(mode="map"), FastEmbedder()
store = VectorStore(config.KB_VECTOR_DB); store.sync(kb._all_chunks(), emb)
chunks, M = store.load(); store.close()
ids = [c["chunk_id"] for c in chunks]
labels = json.loads((ROOT / "verification/relevance_labels.json").read_text(encoding="utf-8"))
full = list(range(len(ids))); filtered = [i for i, c in enumerate(ids) if not DROP.search(c)]

for name, pool, alt in [("A full/current", full, False), ("B full/+alt", full, True),
                        ("C filtered/current", filtered, False), ("D filtered/+alt", filtered, True)]:
    per = {}
    for cwe in W:
        s = M @ emb.embed_query(query(cwe, alt))
        top = sorted(pool, key=lambda i: -s[i])[:2]
        per[cwe] = sum(labels.get(cwe, {}).get(ids[i]) == 2 for i in top) / 2
    macro = sum(per.values()) / len(per)
    weighted = sum(per[c] * W[c] for c in W) / sum(W.values())
    print(f"{name:20s} macroP@2={macro:.2f} alertWeightedP@2={weighted:.2f} "
          + " ".join(f"{c[4:]}:{p:.1f}" for c, p in per.items()))
```
