"""The full triage report as a PDF: every alert of a saved run, grouped for a developer.

    python -m triagebot report [--run RUN] [--out PATH]

Reads a saved run (evidence/experiments/<run>/) and its case set. Makes no model
calls and never reads the OWASP answer key: the report shows TriageBot's own
decisions, as a developer would receive them, not a score.

Three groups, in the order a developer acts on them:
  1. To fix          confirmed vulnerabilities, with the cited lines that prove them
  2. Closed          false alarms, with the reason and the lines that show it
  3. For a person    alerts TriageBot would not decide, with why
"""
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re

from triagebot import config

DEFAULT_RUN = "6-after"
DEFAULT_OUT_DIR = Path(__file__).resolve().parents[1] / "Context" / "tmp" / "reports"   # git-ignored
MAX_CITATIONS = 5              # cited lines shown per alert
_REPO_ROOT = Path(__file__).resolve().parents[1]

CWE_NAMES = {
    "CWE-22": "Path traversal", "CWE-78": "Command injection", "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection", "CWE-90": "LDAP injection", "CWE-643": "XPath injection",
    "CWE-327": "Weak cryptography", "CWE-328": "Weak hashing", "CWE-330": "Weak randomness",
    "CWE-501": "Trust boundary violation", "CWE-614": "Insecure cookie",
}
GROUPS = (
    ("true_positive", "To fix: confirmed vulnerabilities",
     "TriageBot traced untrusted input to a dangerous call with no effective protection.", (179, 38, 30)),
    ("false_positive", "Closed: false alarms",
     "TriageBot found why the alert cannot be exploited. Spot-check the reason before closing.", (46, 125, 79)),
    ("human_review", "For a person: needs human review",
     "TriageBot would not decide these automatically. A security reviewer should look at each one.",
     (217, 130, 43)),
)
NAVY, GREY, LIGHT = (20, 49, 92), (91, 102, 115), (243, 245, 247)

# Core PDF fonts are Latin-1 only; map the characters model text commonly uses.
_ASCII = str.maketrans({"…": "...", "—": "-", "–": "-", "‘": "'", "’": "'",
                        "“": '"', "”": '"', "→": "->", "←": "<-", "≤": "<=",
                        "≥": ">=", "≠": "!=", " ": " ", "•": "-", "×": "x"})


class ReportUnavailable(Exception):
    """The saved run or its case set is missing."""


def _latin1(text) -> str:
    return str(text or "").translate(_ASCII).encode("latin-1", "replace").decode("latin-1")


def _type(cwe: str) -> str:
    return CWE_NAMES.get(cwe, cwe or "Unknown type")


def _escalation_reason(validated: dict) -> str:
    """Why an alert went to a person: the validator's findings, else the council's own doubt."""
    errors = [e for e in validated.get("validation_errors") or [] if e]
    if errors:
        return "Automatic checks failed: " + "; ".join(str(e) for e in errors)
    if validated.get("original_verdict") == "human_review":
        return "The council could not decide from the evidence."
    return "Sent for human review."


# --- per-finding helpers (deterministic; no model calls) -------------------------

VOTE = {"true_positive": "real", "false_positive": "false alarm", "human_review": "unsure"}
_SOURCE_RE = re.compile(r"request\.get|getParameter|getHeader|getCookies|getQueryString|getInputStream|"
                        r"getReader|getPathInfo|getRequestURI|nextElement")
_SINK_RE = re.compile(r"exec\(|execute\w*\(|prepareStatement|prepareCall|batchUpdate|query\w*\(|update\(|"
                      r"getWriter|\.print|\.write\(|\.format\(|new (?:java\.io\.)?File\b|Paths\.get|"
                      r"File(?:In|Out)putStream|\.search\(|evaluate\(|sendRedirect|forward\(|addCookie|ProcessBuilder|\.start\(\)|"
                      r"getInstance\(|nextInt|nextDouble|nextLong|nextFloat|nextGaussian|setAttribute|putValue")
_GUARD_RE = re.compile(r"escape|encode|saniti|htmlEscape|ESAPI|PreparedStatement|setString|\?\s*\S.*:|"
                       r"\bif\s*\(|switch\s*\(|case\s|=\s*\"[^\"]*\";$", re.I)
_CONCAT_RE = re.compile(r"[\"']\s*\+\s*\w|\w\s*\+\s*[\"']")
_REF = re.compile(r"\s*\[REF-\d+\]")
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z'\"(])")
FIX_PHASES = ("Implementation", "Architecture and Design")
_catalogue = None


def _role(quote: str, verdict: str) -> str:
    """A label for a cited line, from what the code on it does."""
    if verdict == "false_positive" and _GUARD_RE.search(quote):
        return "GUARD"
    if _SOURCE_RE.search(quote):
        return "SOURCE"
    if _SINK_RE.search(quote):
        return "SINK"
    if _CONCAT_RE.search(quote):
        return "BUILDS"
    return "STEP"


def _split(explanation: str) -> tuple[str, str]:
    """(first sentence, the rest) of a model explanation."""
    sentences = _SENTENCE.split(" ".join((explanation or "").split()))
    return sentences[0] if sentences else "", " ".join(sentences[1:])


def _council(council: dict, final: str) -> str:
    """How the Analyst, Skeptic and Chair voted, and what that says about confidence."""
    votes = {r.get("role"): r.get("verdict") for r in council.get("role_reports") or []}
    analyst, skeptic = votes.get("analyst"), votes.get("skeptic")
    if not analyst or not skeptic:
        return ""
    head = f"Analyst: {VOTE.get(analyst, analyst)}  -  Skeptic: {VOTE.get(skeptic, skeptic)}  ->  "
    if final == "human_review":
        return head + "no confident decision; sent to a person"
    if analyst == skeptic == final:
        return head + "unanimous (high confidence)"
    if analyst == skeptic:
        return head + f"the Chair overruled both: {VOTE.get(final, final)} (check this one first)"
    return head + f"split; the Chair decided: {VOTE.get(final, final)} (check this one first)"


def _verification(validated: dict, citations: list) -> str:
    repairs = [r for r in validated.get("validation_repairs") or [] if r]
    if validated.get("validated"):
        text = f"All {len(citations)} cited line{'s' if len(citations) != 1 else ''} verified in the source by code"
    elif validated.get("validation_errors"):
        text = "Citation check failed; decision withheld"
    else:
        text = "Not automatically decided"
    if repairs:
        text += f" (guidance label auto-corrected{f' x{len(repairs)}' if len(repairs) > 1 else ''})"
    return text


def _mitre_url(cwe: str) -> str:
    digits = re.findall(r"\d+", cwe or "")
    return f"https://cwe.mitre.org/data/definitions/{digits[0]}.html" if digits else ""


def _recommended_fix(cwe: str, limit: int = 1) -> list[str]:
    """MITRE's own Potential Mitigations for the CWE (code-level phases first), shortened.

    Deterministic and maintained by MITRE, not by us. Empty when the catalogue is not
    installed or has no code-level mitigation; the report then shows the link alone.
    """
    global _catalogue
    if _catalogue is None:
        try:
            from triagebot.nodes.context.cwe_catalogue import CweCatalogue
            _catalogue = CweCatalogue()
        except (FileNotFoundError, OSError, ValueError, ImportError):
            _catalogue = False
    entry = _catalogue.lookup(cwe) if _catalogue else None
    if not entry:
        return []
    fixes = []
    for mitigation in entry.get("mitigations", []):
        if not set(mitigation.get("phases", [])) & set(FIX_PHASES):
            continue
        sentences = _SENTENCE.split(_REF.sub("", mitigation.get("text", "")))
        text = " ".join(sentences[:2])
        fixes.append(text if len(text) <= 320 else text[:317].rstrip() + "...")
        if len(fixes) == limit:
            break
    return fixes


def load_report(run=DEFAULT_RUN, out_root=None) -> dict:
    """Every alert of a saved run with its final (validated) decision. No answer key."""
    folder = Path(out_root or config.EXPERIMENTS_OUT) / run
    results_file, manifest_file = folder / "results.jsonl", folder / "run_manifest.json"
    if not results_file.is_file() or not manifest_file.is_file():
        raise ReportUnavailable(f"no saved results for run {run} under {folder.parent}")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    sample = Path(manifest["case_set"]["file"])
    sample = sample if sample.is_absolute() else _REPO_ROOT / sample
    if not sample.is_file():
        raise ReportUnavailable(f"the run's case set is missing: {sample}")
    alerts = json.loads(sample.read_text(encoding="utf-8"))
    alerts = {a["case_id"]: a for a in (alerts["alerts"] if isinstance(alerts, dict) else alerts)}

    findings = []
    for line in results_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        council = record.get("council")
        if not council or record["case_id"] not in alerts:
            continue
        validated, chair = council.get("validated") or {}, council.get("review") or {}
        verdict = validated.get("verdict")
        if verdict not in ("true_positive", "false_positive"):
            verdict = "human_review"            # anything undecided is a person's call
        alert = alerts[record["case_id"]]
        findings.append({
            "case_id": record["case_id"],
            "type": _type(alert.get("cwe", "")),
            "cwe": alert.get("cwe", ""),
            "file": alert.get("file", ""),
            "line": alert.get("start_line"),
            "rule": alert.get("rule_id", ""),
            "message": alert.get("message", ""),
            "verdict": verdict,
            "explanation": validated.get("explanation") or chair.get("explanation", ""),
            "citations": validated.get("citations") or chair.get("citations") or [],
            "guidance": validated.get("guidance") or [],
            "escalation": _escalation_reason(validated) if verdict == "human_review" else "",
            "council": _council(council, validated.get("verdict") or verdict),
            "verification": _verification(validated, validated.get("citations") or []),
            "fix": _recommended_fix(alert.get("cwe", "")) if verdict == "true_positive" else [],
            "mitre_url": _mitre_url(alert.get("cwe", "")),
            "seconds": chair.get("latency_seconds") or 0.0,
            "cost": (chair.get("usage") or {}).get("cost") or 0.0,
        })
    if not findings:
        raise ReportUnavailable(f"run {run} has no council results to report")
    findings.sort(key=lambda f: f["case_id"])
    models = (manifest.get("model") or {}).get("reported") or [(manifest.get("model") or {}).get("requested")]
    return {"run": run, "finished_at": (manifest.get("finished_at") or "")[:10],
            "model": ", ".join(m for m in models if m), "case_set": manifest["case_set"].get("name", ""),
            "findings": findings}


# --- PDF ----------------------------------------------------------------------

def _pdf_class():
    try:
        from fpdf import FPDF
    except ImportError as error:
        raise ReportUnavailable("the PDF report needs fpdf2: pip install -r requirements.txt") from error

    class ReportPDF(FPDF):
        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*GREY)
            self.cell(0, 6, f"TriageBot triage report  -  page {self.page_no()}/{{nb}}", align="C")

    return ReportPDF


def _heading(pdf, text, size=16, colour=NAVY):
    pdf.set_font("Helvetica", "B", size)
    pdf.set_text_color(*colour)
    pdf.multi_cell(0, size * 0.5, _latin1(text), align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)


def _body(pdf, text, size=9.5, style="", colour=(28, 35, 43), height=4.6):
    pdf.set_font("Helvetica", style, size)
    pdf.set_text_color(*colour)
    pdf.multi_cell(0, height, _latin1(text), align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)


def _summary(pdf, report):
    findings = report["findings"]
    counts = Counter(f["verdict"] for f in findings)
    _heading(pdf, "TriageBot triage report", 22)
    pdf.ln(2)
    _body(pdf, f"{len(findings)} Semgrep alerts reviewed by the TriageBot council "
               f"(Analyst and Skeptic, then a Chair), with every citation checked by code.", 11)
    _body(pdf, f"Run {report['run']} ({report['case_set']}, finished {report['finished_at']})  -  "
               f"model {report['model']}  -  report generated "
               f"{datetime.now().strftime('%Y-%m-%d %H:%M')}", 8.5, colour=GREY)
    pdf.ln(5)

    width = (pdf.w - pdf.l_margin - pdf.r_margin - 8) / 3
    top = pdf.get_y()
    for i, (verdict, title, _, colour) in enumerate(GROUPS):
        x = pdf.l_margin + i * (width + 4)
        pdf.set_fill_color(*LIGHT)
        pdf.rect(x, top, width, 26, style="F")
        pdf.set_fill_color(*colour)
        pdf.rect(x, top, width, 1.6, style="F")
        pdf.set_xy(x + 4, top + 4)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(*colour)
        pdf.cell(width - 8, 10, str(counts.get(verdict, 0)))
        pdf.set_xy(x + 4, top + 15)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(28, 35, 43)
        pdf.multi_cell(width - 8, 4.2, _latin1(title), align="L")
    pdf.set_y(top + 32)

    _heading(pdf, "By vulnerability type", 12)
    pdf.ln(1)
    types = sorted({f["type"] for f in findings})
    pdf.set_fill_color(*LIGHT)
    pdf.set_draw_color(214, 222, 234)
    with pdf.table(col_widths=(46, 20, 20, 24, 18), text_align=("LEFT", "RIGHT", "RIGHT", "RIGHT", "RIGHT"),
                   line_height=5.5, first_row_as_headings=False, cell_fill_mode="ROWS", cell_fill_color=LIGHT) as table:
        pdf.set_font("Helvetica", "B", 9)
        table.row(("Type", "To fix", "Closed", "For a person", "Total"))
        pdf.set_font("Helvetica", "", 9)
        for name in types:
            group = Counter(f["verdict"] for f in findings if f["type"] == name)
            table.row((name, str(group["true_positive"]), str(group["false_positive"]),
                       str(group["human_review"]), str(sum(group.values()))))
        pdf.set_font("Helvetica", "B", 9)
        table.row(("All types", str(counts["true_positive"]), str(counts["false_positive"]),
                   str(counts["human_review"]), str(len(findings))))
    pdf.ln(4)

    seconds = sum(f["seconds"] for f in findings)
    cost = sum(f["cost"] for f in findings)
    _body(pdf, f"Model cost US${cost:.2f} in total (US${cost / len(findings):.3f} per alert); "
               f"recorded review time {seconds / len(findings):.1f} s per alert on average.", 9)
    pdf.ln(3)
    _heading(pdf, "How to read this report", 12)
    pdf.ln(1)
    for line in (
        "Every decision quotes the source lines it relies on, and code has checked that each quote "
        "exists in the cited file. Any decision that failed that check was moved to 'For a person'.",
        "TriageBot only reviews what Semgrep flagged: it cannot find vulnerabilities the scanner missed.",
        "TriageBot is decision support. Read the reason before closing a false alarm; it is not "
        "a guarantee that the code is safe.",
    ):
        _body(pdf, "-  " + line, 9)
        pdf.ln(0.8)


LABEL_W = 26                   # mm: the grey label column of each finding
_PATH_PREFIX = re.compile(r"^(?:src/main/java/)?(?:[a-z0-9_]+/)*")    # package folders -> file name


def _short_path(path: str) -> str:
    return _PATH_PREFIX.sub("", path or "") or path


def _labelled(pdf, label, text, *, size=9, style="", colour=(28, 35, 43), font="Helvetica",
              height=4.4, label_colour=GREY, fill=False):
    """One row: a small grey label on the left, wrapped content on the right."""
    if pdf.get_y() > pdf.h - 24:
        pdf.add_page()
    top = pdf.get_y()
    pdf.set_font("Helvetica", "B", 6.8)
    pdf.set_text_color(*label_colour)
    pdf.set_xy(pdf.l_margin, top + 0.4)
    pdf.cell(LABEL_W - 2, 3.6, _latin1(label.upper()))
    pdf.set_xy(pdf.l_margin + LABEL_W, top)
    pdf.set_font(font, style, size)
    pdf.set_text_color(*colour)
    if fill:
        pdf.set_fill_color(*LIGHT)
    pdf.multi_cell(pdf.w - pdf.r_margin - pdf.l_margin - LABEL_W, height, _latin1(text), align="L",
                   fill=fill, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(0.9)


def _finding(pdf, finding, colour):
    if pdf.get_y() > pdf.h - 70:
        pdf.add_page()
    verdict = finding["verdict"]
    # Header: what and where, in one line; the scanner's rule small underneath.
    pdf.set_fill_color(*colour)
    pdf.rect(pdf.l_margin, pdf.get_y() + 0.5, 1.4, 5, style="F")
    pdf.set_x(pdf.l_margin + 3)
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.cell(0, 6, _latin1(f"{finding['type']}  -  {_short_path(finding['file'])}:{finding['line']}"),
             align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(pdf.l_margin + 3)
    _body(pdf, f"{finding['case_id']}  -  {finding['cwe']}  -  Semgrep rule {finding['rule'].split('.')[-1]}",
          7.5, colour=GREY, height=3.6)
    pdf.ln(1.5)

    if finding["escalation"]:
        _labelled(pdf, "Why a person", finding["escalation"], style="B", colour=colour)
    summary, details = _split(finding["explanation"])
    _labelled(pdf, {"true_positive": "Summary", "false_positive": "Why it's safe",
                    "human_review": "What's unclear"}[verdict], summary, style="B")

    citations = sorted(finding["citations"], key=lambda c: (c.get("file", ""), c.get("line") or 0))
    shown = citations[:MAX_CITATIONS]
    for citation in shown:
        quote = " ".join(str(citation.get("quote", "")).split())
        role = _role(quote, verdict)
        name = Path(citation.get("file", "")).name
        prefix = "" if name == Path(finding["file"]).name else f"{name}:"
        _labelled(pdf, role,
                  f"{prefix}L{citation.get('line')}  {quote}", size=7.6, font="Courier", height=3.7,
                  fill=True, label_colour=colour if role in ("SINK", "GUARD") else GREY)
    if len(citations) > len(shown):
        extra = len(citations) - len(shown)
        _labelled(pdf, "", f"+{extra} more cited line{'s' if extra > 1 else ''}", size=7.5, colour=GREY)

    if details:
        _labelled(pdf, "Details", details, size=8.5, colour=(60, 68, 78))
    if verdict == "true_positive":
        for i, fix in enumerate(finding["fix"]):
            _labelled(pdf, "Recommended fix" if i == 0 else "", fix, size=8.5)
        source = f"MITRE {finding['cwe']}: {finding['mitre_url']}" if finding["mitre_url"] else ""
        if source:
            _labelled(pdf, "" if finding["fix"] else "Recommended fix",
                      ("General guidance from " if finding["fix"] else "See ") + source, size=7.5, colour=GREY)
    if finding["council"]:
        _labelled(pdf, "Council", finding["council"], size=8.5)
    _labelled(pdf, "Verification", finding["verification"], size=8.5)
    guidance = [g for g in finding["guidance"] if g.get("doc") or g.get("section")]
    if guidance:
        _labelled(pdf, "Reference", "; ".join(
            f"{g.get('doc', '')} - {g.get('section', '')}".strip(" -") for g in guidance[:3]),
            size=7.5, colour=GREY)
    pdf.ln(2)
    pdf.set_draw_color(214, 222, 234)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(4)


def build_pdf(report: dict, out: Path) -> Path:
    """Write the report to ``out`` and return the path."""
    pdf = _pdf_class()(format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(16, 16, 16)
    pdf.alias_nb_pages()
    pdf.set_title("TriageBot triage report")
    pdf.add_page()
    _summary(pdf, report)
    for verdict, title, intro, colour in GROUPS:
        group = [f for f in report["findings"] if f["verdict"] == verdict]
        pdf.add_page()
        _heading(pdf, f"{title} ({len(group)})", 16, colour)
        pdf.ln(1)
        _body(pdf, intro, 9.5, colour=GREY)
        pdf.ln(4)
        if not group:
            _body(pdf, "None in this run.", 10)
        for finding in group:
            _finding(pdf, finding, colour)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out))
    return out


def default_out(run=DEFAULT_RUN) -> Path:
    return DEFAULT_OUT_DIR / f"triagebot-report-{run}.pdf"
