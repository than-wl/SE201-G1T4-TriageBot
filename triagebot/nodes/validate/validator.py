"""Deterministic validation gate (owner: Lisa).

Pure code, no LLM: checks the verdict's JSON shape and verifies every
citation (file, line, quote) against the actual source. Unsupported or
malformed output falls back to human_review with reasons — never silently
passed, never converted to false_positive.

Works for single-agent and council output alike. Offline: no network, no file
or answer-key access. The caller supplies, per case, the expected file name and
the exact source text the model was shown, and optionally the retrieved
guidance chunks ("guidance_chunks") that were listed in the evidence block.

Accepted result shape: case_id, verdict, explanation and citations are
required; role, guidance, latency_seconds, usage and model are optional
(review/report.py stamps role and guidance on every AgentReport). Any other
key is rejected.

Guidance rule (design decision 15): guidance is a list of
{chunk_id, doc, section, url}; every ref must name a supplied chunk and copy
its doc, section and url exactly. Refs without supplied chunks cannot be
verified and are rejected; an empty or missing guidance list is valid.

Validated records carry guidance through (else []), and always carry
latency_seconds, usage, model and role when present, since the call's cost was
spent whether or not validation passed.
"""
import json
import re

VERDICTS = ("true_positive", "false_positive", "human_review")
RESULT_KEYS = {"case_id", "verdict", "explanation", "citations"}
BODY_KEYS = RESULT_KEYS - {"case_id"}
OPTIONAL_KEYS = {"role", "guidance", "latency_seconds", "usage", "model"}
CARRIED_KEYS = ("latency_seconds", "usage", "model", "role")  # kept on pass and fail
CITATION_KEYS = {"file", "line", "quote"}
GUIDANCE_KEYS = {"chunk_id", "doc", "section", "url"}
FALLBACK_EXPLANATION = "Validation failed; human review required."
UNGROUNDED_ERROR = "No CWE-matched guidance for this alert; routed to human review"

# Only dotted identifiers (optionally ending in "()") in backticks are checked; SQL or prose is skipped.
_BACKTICKED = re.compile(r"`([^`\n]+)`")
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\(\))?")


def _identifier_errors(explanation, source):
    errors = []
    for span in _BACKTICKED.findall(explanation):
        name = span.strip()
        if not _IDENTIFIER.fullmatch(name):
            continue
        for part in name.removesuffix("()").split("."):
            if not re.search(r"(?<![\w$])" + re.escape(part) + r"(?![\w$])", source):
                errors.append(f"Explanation names `{name}` but '{part}' does not appear in the source")
                break
    return errors


def _guidance_errors(guidance, guidance_chunks):
    if not isinstance(guidance, list):
        return ["Invalid guidance (expected a list)"]
    errors = []
    for number, ref in enumerate(guidance, 1):
        if not isinstance(ref, dict) or set(ref) != GUIDANCE_KEYS:
            errors.append(f"Guidance {number}: invalid shape")
        elif guidance_chunks is not None:
            chunk = next((c for c in guidance_chunks if c.get("chunk_id") == ref["chunk_id"]), None)
            if chunk is None:
                errors.append(f"Guidance {number}: chunk_id is not one of the retrieved chunks")
            elif any(ref[key] != chunk.get(key) for key in ("doc", "section", "url")):
                errors.append(f"Guidance {number}: doc, section or url does not match chunk {ref['chunk_id']}")
    if guidance and guidance_chunks is None:
        errors.append("Cannot verify guidance references (no guidance_chunks supplied)")
    return errors


def check_body(value, file, source, require_case_id=False, guidance_chunks=None):
    """Validate verdict, explanation, citations and guidance of one result; return a list of error strings."""
    expected = RESULT_KEYS if require_case_id else BODY_KEYS
    if not isinstance(value, dict) or not expected <= set(value):
        return ["Invalid result shape (expected: " + ", ".join(sorted(expected))
                + "; optional: " + ", ".join(sorted(OPTIONAL_KEYS)) + ")"]
    errors = []
    unexpected = set(value) - expected - OPTIONAL_KEYS
    if unexpected:
        errors.append("Unexpected field(s): " + ", ".join(sorted(map(str, unexpected))))
    if "guidance" in value:
        errors.extend(_guidance_errors(value["guidance"], guidance_chunks))
    if value["verdict"] not in VERDICTS:  # unhashable/odd types simply fail the membership test
        errors.append("Invalid verdict")
    explanation = value["explanation"]
    if not isinstance(explanation, str) or not explanation.strip():
        errors.append("Missing explanation")
    citations = value["citations"]
    if not isinstance(citations, list) or not citations:
        return errors + ["Missing citations"]
    lines = source.splitlines()
    for number, c in enumerate(citations, 1):
        if not isinstance(c, dict) or set(c) != CITATION_KEYS:
            errors.append(f"Citation {number}: invalid shape")
        elif c["file"] != file:
            errors.append(f"Citation {number}: wrong file")
        elif type(c["line"]) is not int or not 1 <= c["line"] <= len(lines):
            errors.append(f"Citation {number}: line out of range")
        elif not isinstance(c["quote"], str) or not c["quote"].strip():
            errors.append(f"Citation {number}: empty quote")
        elif c["quote"] not in lines[c["line"] - 1]:
            errors.append(f"Citation {number}: quote is not an exact substring of line {c['line']}")
    if isinstance(explanation, str) and explanation.strip():
        errors.extend(_identifier_errors(explanation, source))
    return errors


def _items(parsed, only_case):
    """Normalise the accepted shapes to (items, error). Items are not yet validated."""
    if isinstance(parsed, list):
        return parsed, None
    if isinstance(parsed, dict) and isinstance(parsed.get("cases"), list) and set(parsed) == {"cases"}:
        return parsed["cases"], None
    if isinstance(parsed, dict) and "case_id" in parsed:
        return [parsed], None
    if isinstance(parsed, dict) and BODY_KEYS <= set(parsed) and only_case:
        return [dict(parsed, case_id=only_case)], None  # single-case output without an ID
    return [], "Unrecognised top-level shape (expected a list, {'cases': [...]} or one result object)"


def _record(case_id, original, errors, value=None):
    ok = not errors
    record = {
        "case_id": case_id,
        "verdict": value["verdict"] if ok else "human_review",
        "original_verdict": original,
        "validated": ok,
        "explanation": value["explanation"] if ok else FALLBACK_EXPLANATION,
        "citations": value["citations"] if ok else [],
        "guidance": value.get("guidance", []) if ok else [],
        "validation_errors": errors,
    }
    for key in CARRIED_KEYS:  # the call's cost was spent whether or not validation passed
        if value is not None and key in value:
            record[key] = value[key]
    return record


def validate_results(raw, cases):
    """Validate a model output (JSON text or parsed) against ``cases``.

    ``cases`` maps each requested case_id to ``{"file": expected_file, "source": source_text}``, plus an
    optional ``"guidance_chunks"``: the retrieved chunks shown to the model, used to verify guidance refs.
    Returns ``{"results": [...], "batch_errors": [...], "unknown_case_ids": [...]}`` with exactly one
    compact record per requested case, in request order.
    """
    if not isinstance(cases, dict) or not cases:
        raise ValueError("cases must be a non-empty mapping of case_id -> {'file', 'source'}")
    batch_errors, unknown = [], []
    parsed = raw
    if isinstance(raw, (str, bytes)):
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            parsed, batch_errors = None, ["Malformed JSON"]
    elif raw is None:
        batch_errors = ["Missing model output"]
    items = []
    if not batch_errors:
        only_case = next(iter(cases)) if len(cases) == 1 else None
        items, problem = _items(parsed, only_case)
        if problem:
            batch_errors.append(problem)

    by_case = {case_id: [] for case_id in cases}
    for item in items:
        case_id = item.get("case_id") if isinstance(item, dict) else None
        if isinstance(case_id, str) and case_id in by_case:
            by_case[case_id].append(item)
        else:
            shown = case_id if isinstance(case_id, str) else repr(case_id)
            unknown.append(shown)
            batch_errors.append(f"Unknown or missing case_id: {shown}")

    results = []
    for case_id, found in by_case.items():
        if batch_errors and not items:
            results.append(_record(case_id, None, ["Batch output unusable: " + batch_errors[0]]))
        elif not found:
            results.append(_record(case_id, None, ["No result returned for this case"]))
        elif len(found) > 1:
            batch_errors.append(f"Duplicate results for case {case_id}")
            results.append(_record(case_id, None, [f"Duplicate results ({len(found)}) for this case"]))
        else:
            item = found[0]
            original = item["verdict"] if item.get("verdict") in VERDICTS else None
            case = cases[case_id]
            errors = check_body(item, case["file"], case["source"], require_case_id=True,
                                guidance_chunks=case.get("guidance_chunks"))
            if case.get("guidance_matched") is False:
                # Ungrounded alerts never get an automatic verdict, whatever the model said.
                errors.append(UNGROUNDED_ERROR)
            results.append(_record(case_id, original, errors, item))
    return {"results": results, "batch_errors": batch_errors, "unknown_case_ids": unknown}
