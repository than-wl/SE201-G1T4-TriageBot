"""Free retrieval-quality check of the semantic set-up rules R1 to R5 (step 4, item 2).

Did the set-up rules (design decision 28) make semantic search return better
guidance, and does it find the right guidance for weaknesses outside the
benchmark? No model calls: only the local embedder, the installed MITRE
catalogue and the prepared vector store. It does not measure verdict accuracy.

Configurations: `original` (all five rules off, decision 21), `+R1` .. `+R5`
(original plus one rule) and `improved` (the `semantic` profile). Each is applied
with profiles.applied() and run through KnowledgeBase.semantic_plan() and
retrieve(), the same code paths a real run and `--explain` use.

Part A, the 9 scan CWEs of verification/relevance_labels.json, graded:
  - search ranking: the top 6 searched chunks by cosine, ignoring the budget
    (the MITRE chunk is attached by ID, never searched, so it is never in it);
  - pack: what retrieve() returns after the budget.
Part B, ten CWEs outside the scan, each with a sheet dedicated to it (PART_B,
fixed in advance): is that sheet in the pack? No grading needed.

Two phases, with a grading pause in between:

    python verification/semantic_setup_check.py --phase list
        writes verification/relevance_to_grade.json: every non-MITRE chunk in any
        search ranking or pack, for any configuration, with no grade for its CWE.
        Blind: no configuration, rank or score is recorded.
    python verification/semantic_setup_check.py --phase score
        merges relevance_labels.json with relevance_labels_added.json (stops if
        a needed grade is missing) and writes
        evidence/retrieval/semantic_setup_check.{json,md}.
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagebot import config, profiles  # noqa: E402
from triagebot.nodes.context.retrieval import excluded_docs, load_scope  # noqa: E402

VERIFICATION = ROOT / "verification"
LABELS = VERIFICATION / "relevance_labels.json"
ADDED_LABELS = VERIFICATION / "relevance_labels_added.json"
TO_GRADE = VERIFICATION / "relevance_to_grade.json"
EVIDENCE = ROOT / "evidence" / "retrieval"
OUT_JSON = EVIDENCE / "semantic_setup_check.json"
OUT_MD = EVIDENCE / "semantic_setup_check.md"
RERUN = "python verification/semantic_setup_check.py --phase score"

MITRE_DOC = "MITRE_CWE"
SEARCH_DEPTH = 6                        # the search ranking: top 6 by cosine, ignoring the budget
RUBRIC = {"2": "guidance about this weakness", "1": "adjacent", "0": "not relevant"}
META_FIELDS = ("grader", "blind", "rubric", "date")

# The switch each rule turns on (its value is taken from the improved set-up).
RULES = {
    "R1": "SEMANTIC_QUERY_ALT_TERMS",
    "R2": "SEMANTIC_MITRE_GUIDANCE",
    "R3": "SEMANTIC_KB_SCOPE",
    "R4": "SEMANTIC_MAX_CHUNK_CHARS",
    "R5": "SEMANTIC_GROUNDING",
}

# Part B, fixed before any result was seen. Rule: CWEs not in the scan for which the
# knowledge base has a sheet dedicated to that one weakness. Do not edit after seeing results.
PART_B = (
    ("CWE-918", "Server_Side_Request_Forgery_Prevention_Cheat_Sheet"),
    ("CWE-611", "XML_External_Entity_Prevention_Cheat_Sheet"),
    ("CWE-502", "Deserialization_Cheat_Sheet"),
    ("CWE-352", "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet"),
    ("CWE-601", "Unvalidated_Redirects_and_Forwards_Cheat_Sheet"),
    ("CWE-1336", "Server_Side_Template_Injection_Prevention_Cheat_Sheet"),
    ("CWE-915", "Mass_Assignment_Cheat_Sheet"),
    ("CWE-1021", "Clickjacking_Defense_Cheat_Sheet"),
    ("CWE-434", "File_Upload_Cheat_Sheet"),
    ("CWE-943", "NoSQL_Security_Cheat_Sheet"),
)
PART_B_CONFIGS = ("original", "improved")

# CWE-79's alternate terms include "CSS" (MITRE's old abbreviation for cross-site scripting).
CSS_CWE = "CWE-79"
CSS_CONFIGS = ("+R1", "improved")
_CSS = re.compile(r"\bcss\b|style ?sheets?", re.IGNORECASE)


class GradingError(RuntimeError):
    """A needed grade is missing, invalid or contradicts the original labels."""


# --- configurations ---------------------------------------------------------------------

def configurations() -> dict[str, dict]:
    """original, +R1 .. +R5 (original plus one rule at its improved value), improved."""
    original = profiles.SEMANTIC_SETUPS["original"]
    improved = profiles.SEMANTIC_SETUPS["improved"]
    configs = {"original": dict(original)}
    for rule, key in RULES.items():
        configs[f"+{rule}"] = {**original, key: improved[key]}
    configs["improved"] = dict(improved)
    return configs


def cwe_sort_key(cwe: str):
    digits = re.findall(r"\d+", cwe)
    return (int(digits[0]) if digits else 0, cwe)


# --- collection: the same code paths as retrieve() and --explain ------------------------

def collect(kb, cwe: str, settings: dict) -> dict:
    """What semantic retrieval does for one CWE under one set-up.

    ranked: the full search ranking [(chunk, cosine)]; ranking: its top SEARCH_DEPTH
    chunks; pack: what retrieve() returns; mitre: the MITRE chunk in the pack or None.
    """
    with profiles.applied({"RETRIEVAL_MODE": "semantic", **settings}):
        plan = kb.semantic_plan({"cwe": cwe})
        pack = kb.retrieve({"cwe": cwe})["chunks"]
    if [c["chunk_id"] for c in pack] != [c["chunk_id"] for c in plan["chunks"]]:
        raise AssertionError(f"{cwe}: retrieve() and semantic_plan() disagree")
    ranked = [(c, s) for c, s in plan["ranked"] if c["doc"] != MITRE_DOC]
    return {
        "grounded": plan["grounded"],
        "reason": plan["reason"],
        "name": plan["entry"]["name"] if plan["entry"] else None,
        "ranked": ranked,
        "ranking": [c for c, _ in ranked[:SEARCH_DEPTH]],
        "pack": pack,
        "mitre": next((c for c in pack if c["doc"] == MITRE_DOC), None),
    }


def collect_all(kb, cwes, configs: dict) -> dict:
    """{config name: {cwe: collect(...)}}."""
    return {name: {cwe: collect(kb, cwe, settings) for cwe in cwes}
            for name, settings in configs.items()}


# --- phase 1: what needs grading ----------------------------------------------------------

def to_grade(results: dict, labels: dict) -> list[dict]:
    """Every non-MITRE chunk in any ranking or pack with no grade for its CWE.

    Blind: each item has only cwe, chunk_id, doc, section and text; which
    configuration returned it, its rank and its score are not recorded.
    Sorted by CWE (numerically), then chunk_id.
    """
    needed: dict[tuple[str, str], dict] = {}
    for per_cwe in results.values():
        for cwe, got in per_cwe.items():
            for chunk in got["ranking"] + got["pack"]:
                if chunk["doc"] == MITRE_DOC or chunk["chunk_id"] in labels.get(cwe, {}):
                    continue
                needed[(cwe, chunk["chunk_id"])] = {
                    "cwe": cwe, "chunk_id": chunk["chunk_id"], "doc": chunk["doc"],
                    "section": chunk["section"], "text": chunk["text"]}
    return [needed[k] for k in sorted(needed, key=lambda k: (cwe_sort_key(k[0]), k[1]))]


def to_grade_document(items: list[dict]) -> dict:
    return {
        "about": ("Chunks returned by semantic retrieval for the scan CWEs that have no grade "
                  "in verification/relevance_labels.json. Grade each against its CWE and write "
                  "the grades to verification/relevance_labels_added.json, in the same shape as "
                  "relevance_labels.json ({cwe: {chunk_id: grade}}), plus a _meta block "
                  "(grader, blind, rubric, date)."),
        "rubric": RUBRIC,
        "count": len(items),
        "chunks": items,
    }


def counts_by_cwe(items: list[dict], cwes) -> dict[str, int]:
    return {cwe: sum(i["cwe"] == cwe for i in items) for cwe in cwes}


# --- phase 2: grades ----------------------------------------------------------------------

def merge_labels(original: dict, added: dict) -> dict:
    """Both label files as one {cwe: {chunk_id: grade}}; refuses invalid or conflicting grades.

    The added file must carry a _meta block with grader, blind, rubric and date.
    """
    meta = added.get("_meta")
    if not isinstance(meta, dict) or any(field not in meta for field in META_FIELDS):
        raise GradingError(f"{ADDED_LABELS.name} needs a _meta block with {', '.join(META_FIELDS)}")
    merged = {cwe: dict(grades) for cwe, grades in original.items() if not cwe.startswith("_")}
    for cwe, grades in added.items():
        if cwe.startswith("_"):
            continue
        for chunk_id, grade in grades.items():
            if grade not in (0, 1, 2) or isinstance(grade, bool):
                raise GradingError(f"{cwe} {chunk_id}: grade must be 0, 1 or 2, not {grade!r}")
            prior = merged.get(cwe, {}).get(chunk_id)
            if prior is not None and prior != grade:
                raise GradingError(f"{cwe} {chunk_id}: graded {prior} in {LABELS.name} "
                                   f"but {grade} in {ADDED_LABELS.name}")
            merged.setdefault(cwe, {})[chunk_id] = grade
    return merged


def require_grades(results: dict, labels: dict) -> None:
    """Stop when any needed chunk has no grade (a missing grade is never counted as 0)."""
    missing = to_grade(results, labels)
    if missing:
        listed = ", ".join(f"{m['cwe']} {m['chunk_id']}" for m in missing[:10])
        more = f" and {len(missing) - 10} more" if len(missing) > 10 else ""
        raise GradingError(f"{len(missing)} needed chunk(s) have no grade: {listed}{more}")


# --- metrics ------------------------------------------------------------------------------

def precision_at(grades: list[int], k: int) -> float:
    """Share of the first k positions holding a grade-2 chunk (an empty position counts 0)."""
    return sum(g == 2 for g in grades[:k]) / k


def mean_grade(grades: list[int]) -> float | None:
    return sum(grades) / len(grades) if grades else None


def search_metrics(ranking: list[dict], grades: dict) -> dict:
    values = [grades[c["chunk_id"]] for c in ranking]
    return {"p_at_3": precision_at(values, 3), "p_at_6": precision_at(values, 6),
            "mean_grade": mean_grade(values), "chunks": [c["chunk_id"] for c in ranking],
            "grades": values}


def wrong_platform(chunks: list[dict], wrong_docs) -> int:
    """Chunks from sheets scope.json excludes for Java (other platform, retired, attack catalogue)."""
    return sum(c["doc"] in wrong_docs for c in chunks)


def pack_metrics(pack: list[dict], grades: dict) -> dict:
    """The MITRE chunk is not graded; grade counts and grade-2 characters cover OWASP chunks only."""
    mitre = [c for c in pack if c["doc"] == MITRE_DOC]
    owasp = [c for c in pack if c["doc"] != MITRE_DOC]
    owasp_grades = [grades[c["chunk_id"]] for c in owasp]
    return {
        "mitre": bool(mitre),
        "mitre_chars": sum(len(c["text"]) for c in mitre),
        "owasp_chunks": len(owasp),
        "grade_2": sum(g == 2 for g in owasp_grades),
        "grade_ge_1": sum(g >= 1 for g in owasp_grades),
        "chars": sum(len(c["text"]) for c in pack),
        "grade_2_chars": sum(len(c["text"]) for c, g in zip(owasp, owasp_grades) if g == 2),
        "chunks": [c["chunk_id"] for c in pack],
        "grades": owasp_grades,
    }


def _mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def part_a(results: dict, labels: dict, wrong_docs) -> dict:
    """Per CWE and macro-averaged, per configuration."""
    out = {}
    for name, per_cwe in results.items():
        rows = {}
        for cwe, got in per_cwe.items():
            grades = labels[cwe]
            rows[cwe] = {"search": search_metrics(got["ranking"], grades),
                         "pack": pack_metrics(got["pack"], grades),
                         "wrong_platform": {"search": wrong_platform(got["ranking"], wrong_docs),
                                            "pack": wrong_platform(got["pack"], wrong_docs)}}
        macro = {
            "search": {k: _mean(r["search"][k] for r in rows.values())
                       for k in ("p_at_3", "p_at_6", "mean_grade")},
            "pack": {k: _mean(float(r["pack"][k]) for r in rows.values())
                     for k in ("mitre", "mitre_chars", "owasp_chunks", "grade_2", "grade_ge_1",
                               "chars", "grade_2_chars")},
            "wrong_platform": {k: _mean(r["wrong_platform"][k] for r in rows.values())
                               for k in ("search", "pack")},
            "wrong_platform_total": {k: sum(r["wrong_platform"][k] for r in rows.values())
                                     for k in ("search", "pack")},
            "mitre_present": sum(r["pack"]["mitre"] for r in rows.values()),
            "cwes": len(rows),
        }
        out[name] = {"per_cwe": rows, "macro": macro}
    return out


def same_results(a: dict, b: dict) -> bool:
    """Identical rankings and packs (chunk IDs, in order) for every CWE."""
    key = lambda got: ([c["chunk_id"] for c, _ in got["ranked"]], [c["chunk_id"] for c in got["pack"]])
    return a.keys() == b.keys() and all(key(a[cwe]) == key(b[cwe]) for cwe in a)


def css_check(results: dict, labels: dict) -> list[dict]:
    """CWE-79 chunks under +R1 or improved whose text mentions CSS or style sheets.

    A mechanical match only: the excerpt shows whether CSS means styling or
    cross-site scripting. in_original says whether the original set-up returned it too.
    """
    if CSS_CWE not in results["original"]:
        return []
    base = results["original"][CSS_CWE]
    original = {c["chunk_id"] for c in base["ranking"] + base["pack"]}
    found: dict[str, dict] = {}
    for name in CSS_CONFIGS:
        got = results[name][CSS_CWE]
        for where in ("ranking", "pack"):
            for chunk in got[where]:
                match = _CSS.search(chunk["text"]) if chunk["doc"] != MITRE_DOC else None
                if not match:
                    continue
                item = found.setdefault(chunk["chunk_id"], {
                    "chunk_id": chunk["chunk_id"], "section": chunk["section"],
                    "grade": labels[CSS_CWE].get(chunk["chunk_id"]),
                    "in_original": chunk["chunk_id"] in original,
                    "excerpt": _excerpt(chunk["text"], match), "seen_in": []})
                item["seen_in"].append(f"{name} {where}")
    return [found[k] for k in sorted(found)]


def _excerpt(text: str, match, width: int = 120) -> str:
    start, end = max(match.start() - width, 0), min(match.end() + width, len(text))
    flat = " ".join(text[start:end].split())
    return ("... " if start else "") + flat + (" ..." if end < len(text) else "")


def part_b(results: dict, cwe_map: dict) -> list[dict]:
    rows = []
    for cwe, sheet in PART_B:
        row = {"cwe": cwe, "expected_sheet": sheet, "in_cwe_map": cwe in cwe_map}
        for name in PART_B_CONFIGS:
            got = results[name][cwe]
            ranks = [i for i, (c, _) in enumerate(got["ranked"], 1) if c["doc"] == sheet]
            owasp = [c for c in got["pack"] if c["doc"] != MITRE_DOC]
            row["name"] = row.get("name") or got["name"]
            row[name] = {
                "grounded": got["grounded"],
                "reason": None if got["grounded"] else got["reason"],
                "sheet_in_pack": any(c["doc"] == sheet for c in owasp),
                "first_rank": ranks[0] if ranks else None,
                "pack_chunks_from_sheet": sum(c["doc"] == sheet for c in owasp),
                "pack_owasp_chunks": len(owasp),
                "mitre": got["mitre"] is not None,
            }
        rows.append(row)
    return rows


# --- provenance and output ----------------------------------------------------------------

def sha256(path) -> str | None:
    path = Path(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def provenance(labels_path=LABELS, added_path=ADDED_LABELS) -> dict:
    from triagebot.experiments import git_state
    return {
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git": git_state(),
        "cwe_catalogue_sha256": config.CWE_CATALOGUE_SHA256,
        "cwe_catalogue_xml": Path(config.CWE_CATALOGUE_XML).name,
        "cwe_catalogue_xml_sha256": sha256(config.CWE_CATALOGUE_XML),
        "embedding_model": config.EMBEDDING_MODEL,
        "kb_scope_sha256": sha256(config.KB_SCOPE_FILE),
        "relevance_labels_sha256": sha256(labels_path),
        "relevance_labels_added_sha256": sha256(added_path),
        "top_k": config.RETRIEVAL_TOP_K,
        "guidance_max_chars": config.GUIDANCE_MAX_CHARS,
        "search_depth": SEARCH_DEPTH,
    }


def _f(value, digits=2):
    return "-" if value is None else f"{value:.{digits}f}"


def _yn(value):
    return "yes" if value else "no"


def render_markdown(report: dict) -> str:
    prov, a, b = report["provenance"], report["part_a"], report["part_b"]
    git = prov["git"]
    configs = list(a)
    lines = [
        "# Semantic set-up check: retrieval quality (free, no model calls)",
        "",
        f"Generated {prov['date']} by `{RERUN}`. Code: commit "
        f"`{(git.get('commit') or 'unknown')[:12]}`"
        + (" with uncommitted changes." if git.get("dirty") else "."),
        f"MITRE CWE catalogue 5.0 (zip SHA-256 `{prov['cwe_catalogue_sha256'][:12]}…`), embedding "
        f"model `{prov['embedding_model']}`, `scope.json` SHA-256 `{(prov['kb_scope_sha256'] or '')[:12]}…`, "
        f"label files `{(prov['relevance_labels_sha256'] or '')[:12]}…` (original) and "
        f"`{(prov['relevance_labels_added_sha256'] or '')[:12]}…` (added). Budget "
        f"{prov['guidance_max_chars']:,} characters, at most {prov['top_k']} chunks.",
        "",
        "Configurations: `original` is all five rules off (decision 21); `+R1` .. `+R5` are "
        "original plus one rule; `improved` is the `semantic` profile (all five on). "
        "This measures topic relevance of the guidance, not verdict accuracy.",
        "",
        "Grades: 2 = guidance about this weakness, 1 = adjacent, 0 = not relevant. "
        "Precision counts grade 2 only. The search ranking is the top 6 searched chunks by "
        "cosine, ignoring the budget (the MITRE chunk is attached by ID and never searched). "
        "The pack is what `retrieve()` returns. The MITRE chunk is not graded, so the pack's "
        "grade counts and grade-2 characters cover OWASP chunks only; total characters include it.",
        "",
        "**Wrong platform** counts chunks from sheets that `scope.json` tags with a platform "
        "other than Java, or excludes as retired or as the attack catalogue. The rubric grades "
        "topic, not platform (a FastAPI chunk about SQL injection is graded 2), so rule R3's "
        "effect shows in this column, not in precision.",
        "",
        f"## Part A: the {len(next(iter(a.values()))['per_cwe'])} scan CWEs (macro average over CWEs)",
        "",
        "| Configuration | P@3 | P@6 | Mean grade | MITRE in pack | OWASP chunks | Grade 2 | Grade ≥1 "
        "| Pack chars | Grade-2 chars | Wrong platform, search (total) | Wrong platform, pack (total) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in configs:
        m = a[name]["macro"]
        lines.append(
            f"| `{name}` | {_f(m['search']['p_at_3'])} | {_f(m['search']['p_at_6'])} | "
            f"{_f(m['search']['mean_grade'])} | {m['mitre_present']} of {m['cwes']} | "
            f"{_f(m['pack']['owasp_chunks'], 1)} | {_f(m['pack']['grade_2'], 1)} | "
            f"{_f(m['pack']['grade_ge_1'], 1)} | {m['pack']['chars']:,.0f} | "
            f"{m['pack']['grade_2_chars']:,.0f} | {m['wrong_platform_total']['search']} | "
            f"{m['wrong_platform_total']['pack']} |")
    lines += ["", f"`+R5` gives the same rankings and packs as `original`: "
                  f"{_yn(report['plus_r5_matches_original'])} (expected, since every scan CWE has a valid record).",
              "", "## Part A per CWE: original vs improved", "",
              "Each cell is original → improved.", "",
              "| CWE | P@3 | P@6 | Mean grade | MITRE chars | OWASP chunks | Grade 2 | Grade ≥1 "
              "| Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |",
              "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    o_rows, i_rows = a["original"]["per_cwe"], a["improved"]["per_cwe"]
    for cwe in o_rows:
        o, i = o_rows[cwe], i_rows[cwe]
        pair = lambda f: f"{f(o)} → {f(i)}"
        lines.append(
            f"| {cwe} | {pair(lambda r: _f(r['search']['p_at_3']))} | "
            f"{pair(lambda r: _f(r['search']['p_at_6']))} | "
            f"{pair(lambda r: _f(r['search']['mean_grade']))} | "
            f"{pair(lambda r: r['pack']['mitre_chars'])} | "
            f"{pair(lambda r: r['pack']['owasp_chunks'])} | {pair(lambda r: r['pack']['grade_2'])} | "
            f"{pair(lambda r: r['pack']['grade_ge_1'])} | "
            f"{pair(lambda r: format(r['pack']['chars'], ','))} | "
            f"{pair(lambda r: format(r['pack']['grade_2_chars'], ','))} | "
            f"{pair(lambda r: r['wrong_platform']['search'])} | {pair(lambda r: r['wrong_platform']['pack'])} |")
    lines += ["", "## Part A per CWE, every configuration", ""]
    for name in configs:
        lines += [f"**`{name}`**", "",
                  "| CWE | P@3 | P@6 | Mean grade | MITRE | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars "
                  "| Grade-2 chars | Wrong platform, search | Wrong platform, pack |",
                  "| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for cwe, r in a[name]["per_cwe"].items():
            s, p = r["search"], r["pack"]
            lines.append(
                f"| {cwe} | {_f(s['p_at_3'])} | {_f(s['p_at_6'])} | {_f(s['mean_grade'])} | "
                f"{(str(p['mitre_chars']) + ' chars') if p['mitre'] else 'no'} | {p['owasp_chunks']} | "
                f"{p['grade_2']} | {p['grade_ge_1']} | {p['chars']:,} | {p['grade_2_chars']:,} | "
                f"{r['wrong_platform']['search']} | {r['wrong_platform']['pack']} |")
        lines.append("")
    css = report["css_check"]
    lines += ["## CWE-79 \"CSS\" check", "",
              "CWE-79's alternate terms include \"CSS\", MITRE's old abbreviation for cross-site "
              "scripting. Below: every chunk in CWE-79's search ranking or pack under `+R1` or "
              "`improved` whose text mentions CSS or style sheets (a mechanical match; the excerpt "
              "shows which sense is meant).", ""]
    if css:
        lines += ["| Chunk | Section | Grade | Also under original | Seen in | Excerpt |",
                  "| --- | --- | ---: | --- | --- | --- |"]
        for c in css:
            excerpt = c["excerpt"].replace("|", "\\|")
            lines.append(f"| `{c['chunk_id']}` | {c['section'].replace('|', '/')} | {c['grade']} | "
                         f"{_yn(c['in_original'])} | {'; '.join(c['seen_in'])} | {excerpt} |")
    else:
        lines.append("No chunk mentioning CSS or style sheets appears.")
    headline = report["part_b_headline"]
    lines += ["", "## Part B: weaknesses outside the benchmark (no grading needed)", "",
              "Fixed in advance: CWEs not in the scan for which the knowledge base has a sheet "
              "dedicated to that one weakness. \"First rank\" is the rank of the sheet's first "
              "chunk in the full search ranking. \"In the map?\" is for context only.", "",
              f"**Expected sheet in pack: {headline['original']} of {len(b)} (original) vs "
              f"{headline['improved']} of {len(b)} (improved).**", "",
              "| CWE | Name | Expected sheet | In the map? | Original: in pack | first rank | "
              "chunks from it | Improved: in pack | first rank | chunks from it |",
              "| --- | --- | --- | --- | --- | ---: | ---: | --- | ---: | ---: |"]
    for row in b:
        cells = []
        for name in PART_B_CONFIGS:
            r = row[name]
            if not r["grounded"]:
                cells += [f"not grounded ({r['reason']})", "-", "-"]
            else:
                cells += [_yn(r["sheet_in_pack"]), str(r["first_rank"] or "not searched"),
                          f"{r['pack_chunks_from_sheet']} of {r['pack_owasp_chunks']}"]
        lines.append(f"| {row['cwe']} | {row['name'] or 'no valid record'} | `{row['expected_sheet']}` | "
                     f"{_yn(row['in_cwe_map'])} | " + " | ".join(cells) + " |")
    lines += ["", "## Caveats", "",
              "- The grades are AI-produced and unreviewed: the original set by Hong Yi's AI run, "
              "the added set by Claude, done blind.",
              "- There is one grader per label.",
              f"- There are only {len(o_rows)} CWEs in part A.",
              "- This measures topic relevance, not whether guidance changes verdicts (that is "
              "step 4, item 3).", ""]
    return "\n".join(lines)


def build_report(results: dict, labels: dict, wrong_docs, cwe_map: dict, configs: dict,
                 prov: dict) -> dict:
    a = part_a({n: {c: g for c, g in per.items() if c in labels} for n, per in results.items()},
               labels, wrong_docs)
    b = part_b(results, cwe_map)
    return {
        "provenance": prov,
        "configurations": configs,
        "part_a": a,
        "plus_r5_matches_original": same_results(
            {c: g for c, g in results["+R5"].items() if c in labels},
            {c: g for c, g in results["original"].items() if c in labels}),
        "css_check": css_check(results, labels),
        "part_b": b,
        "part_b_headline": {name: sum(r[name]["sheet_in_pack"] for r in b) for name in PART_B_CONFIGS},
    }


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def _read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def scan_cwes(labels: dict) -> list[str]:
    return sorted((c for c in labels if not c.startswith("_")), key=cwe_sort_key)


def run_list(kb, labels: dict, out_path: Path = TO_GRADE) -> dict[str, int]:
    cwes = scan_cwes(labels)
    results = collect_all(kb, cwes, configurations())
    items = to_grade(results, labels)
    _write(out_path, json.dumps(to_grade_document(items), indent=1, ensure_ascii=False) + "\n")
    return counts_by_cwe(items, cwes)


def run_score(kb, labels_path: Path = LABELS, added_path: Path = ADDED_LABELS,
              out_json: Path = OUT_JSON, out_md: Path = OUT_MD, prov: dict | None = None) -> dict:
    if not Path(added_path).is_file():
        raise GradingError(f"{added_path} is missing; grade {TO_GRADE.name} first")
    original = _read_json(labels_path)
    labels = merge_labels(original, _read_json(added_path))
    cwes = scan_cwes(original)
    configs = configurations()
    scan = collect_all(kb, cwes, configs)
    require_grades(scan, labels)
    extra = collect_all(kb, [c for c, _ in PART_B], {n: configs[n] for n in PART_B_CONFIGS})
    results = {name: {**scan[name], **extra.get(name, {})} for name in configs}
    scope = load_scope(Path(kb.kb_dir) / "scope.json")       # the file R3 reads
    wrong_docs = excluded_docs(scope, profiles.SEMANTIC_SETUPS["improved"]["KB_TARGET_PLATFORM"])
    report = build_report(results, {c: labels[c] for c in cwes}, wrong_docs, kb.cwe_map, configs,
                          prov if prov is not None else provenance(labels_path, added_path))
    _write(out_json, json.dumps(report, indent=1, ensure_ascii=False) + "\n")
    _write(out_md, render_markdown(report))
    return report


def _real_kb():
    from triagebot.nodes.context.retrieval import KnowledgeBase
    missing = []
    if not Path(config.CWE_CATALOGUE_XML).is_file():
        missing.append(f"the MITRE CWE catalogue; prepare it with: {profiles.CATALOGUE_COMMAND}")
    if not profiles._vector_store_ready(config.KB_VECTOR_DB):
        missing.append(f"the vector store; prepare it with: {profiles.VECTOR_STORE_COMMAND}")
    if missing:
        raise profiles.ProfileError("missing " + "; ".join(missing))
    return KnowledgeBase(mode="semantic")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--phase", choices=("list", "score"), required=True)
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")      # a Windows console cannot print "≥" or "→"
    try:
        kb = _real_kb()
        if args.phase == "list":
            counts = run_list(kb, _read_json(LABELS))
            print(f"Chunks to grade, per CWE (written to {TO_GRADE.relative_to(ROOT).as_posix()}):")
            for cwe, n in counts.items():
                print(f"  {cwe:<9}{n:>4}")
            print(f"  {'total':<9}{sum(counts.values()):>4}")
            return 0
        report = run_score(kb)
    except (GradingError, profiles.ProfileError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(render_markdown(report))
    print(f"Wrote {OUT_JSON.relative_to(ROOT).as_posix()} and {OUT_MD.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
