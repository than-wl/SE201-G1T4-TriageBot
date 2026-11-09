"""The product demo: ten alerts from the final test, triaged (offline, free).

    python -m triagebot demo [--pace SECONDS] [--step] [--export-svg PATH]

Input -> TriageBot -> output, from the developer's side: the recorded Semgrep scan,
ten of its alerts, TriageBot deciding each one, and the developer's new list
(confirmed vulnerabilities to fix, false alarms closed, any left for a person).

Everything shown is recorded: the scan is the committed Semgrep run and the
verdicts are the saved final-test run (evidence/experiments/<run>/). No model
calls are made. The ten cases are a fixed draw (seed 2026) of 6 real and 4 safe
cases, Semgrep's own false-alarm rate on the four tested types (453 of 1,121).
The seed was chosen with the outcome known; the screen says the cases come from
the final test, not that they are a random sample, and the full final-test
result follows in the presentation.

The answer key is used only to draw the mix and to mark each decision right or
wrong on screen. It is display-side only and never reaches a prompt (design
decision 7).
"""
import json
from pathlib import Path
import random
import re
import time

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from triagebot import config

DEFAULT_RUN = "6-after"
SEED = 2026
REAL_CASES, SAFE_CASES = 6, 4
PROOF_WIDTH = 58               # characters of a proof line that fit beside the case and type
_REPO_ROOT = Path(__file__).resolve().parents[1]

CWE_NAMES = {
    "CWE-22": "Path traversal", "CWE-78": "Command injection", "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection", "CWE-90": "LDAP injection", "CWE-643": "XPath injection",
}
VERDICT_LINE = {
    "true_positive": ("●", "REAL VULNERABILITY", "bold red"),
    "false_positive": ("○", "FALSE ALARM", "bold green"),
    "human_review": ("◐", "SEND TO A PERSON", "bold yellow"),
}
# The best one-line proof is where the input is glued into a query or command; next best,
# the dangerous call itself.
_CONCAT = re.compile(r"[\"']\s*\+\s*\w|\b\w+\s*\+\s*(?:bar|param)\b")
_SINK = re.compile(r"exec\(|execute\w*\(|prepareStatement|prepareCall|batchUpdate|query\w*\(|update\(|"
                   r"getWriter|\.print|\.write|\.format\(|new java\.io\.File|new File|Paths\.get|"
                   r"FileInputStream|FileOutputStream|\.search\(|evaluate\(|compile\(|sendRedirect|forward\(")
_PACKAGE = re.compile(r"\b(?:[a-z]\w*\.){2,}(?=[A-Z])")          # org.owasp.benchmark.helpers.X -> X
# Words that carry a false-alarm verdict's reason.
_REASON = re.compile(r"constant|never|discard|unused|saniti|escap|encod|hardcoded|hard-coded|safe|"
                     r"always|cannot|does not reach|not reach|overwrit|replac", re.I)


class DemoUnavailable(Exception):
    """A saved run, the case set or the answer key the demo needs is missing."""


# --- loading ----------------------------------------------------------------

def pick_cases(case_ids, key, seed=SEED, real=REAL_CASES, safe=SAFE_CASES) -> list[str]:
    """A fixed, reproducible draw of ``real`` vulnerable and ``safe`` safe cases, in shuffled order."""
    rng = random.Random(seed)
    reals = sorted(c for c in case_ids if key[c]["vulnerable"])
    safes = sorted(c for c in case_ids if not key[c]["vulnerable"])
    if len(reals) < real or len(safes) < safe:
        raise DemoUnavailable(f"the case set has {len(reals)} real and {len(safes)} safe cases; "
                              f"the demo needs {real} and {safe}")
    picked = rng.sample(reals, real) + rng.sample(safes, safe)
    rng.shuffle(picked)
    return picked


def _results(folder: Path) -> dict[str, dict]:
    records = {}
    for line in (folder / "results.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            records[record["case_id"]] = record
    return records


def _reason(text: str, limit: int = 170) -> str:
    """The Chair's sentence that states why: the first one with a reason word, else the first."""
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z'\"])", " ".join((text or "").split()))
    sentence = next((s for s in sentences if _REASON.search(s)), sentences[0] if sentences else "")
    sentence = _PACKAGE.sub("", sentence)
    return sentence if len(sentence) <= limit else sentence[:limit - 1].rstrip() + "…"


def _proof(citations: list[dict]) -> dict | None:
    """The citation that best shows the danger: input glued into a query or command, else the
    dangerous call, else the last citation. Package prefixes are dropped for display."""
    if not citations:
        return None
    best = ([c for c in citations if _CONCAT.search(c.get("quote", ""))]
            or [c for c in citations if _SINK.search(c.get("quote", ""))] or citations)[-1]
    quote = _PACKAGE.sub("", " ".join(best.get("quote", "").split()))
    glued = _CONCAT.search(quote)
    if glued and len(quote) > PROOF_WIDTH and glued.start() > PROOF_WIDTH - 20:
        quote = "…" + quote[max(0, len(quote) - PROOF_WIDTH + 1):]    # keep the "+ bar +" in view
    return {**best, "quote": quote}


def load_demo(run=DEFAULT_RUN, seed=SEED, out_root=None, answer_key=None, scan=None) -> dict:
    """Everything the demo shows, from saved files only."""
    out_root = Path(out_root or config.EXPERIMENTS_OUT)
    folder = out_root / run
    if not (folder / "results.jsonl").is_file():
        raise DemoUnavailable(f"no saved results for run {run} under {out_root}")
    manifest = json.loads((folder / "run_manifest.json").read_text(encoding="utf-8"))
    sample = Path(manifest["case_set"]["file"])
    sample = sample if sample.is_absolute() else _REPO_ROOT / sample
    alerts = json.loads(sample.read_text(encoding="utf-8"))
    alerts = {a["case_id"]: a for a in (alerts["alerts"] if isinstance(alerts, dict) else alerts)}

    key_path = Path(answer_key or config.ANSWER_KEY or "")
    if not key_path.is_file():
        raise DemoUnavailable(f"the answer key is needed to draw the demo's mix: {key_path or 'not set'}")
    from triagebot.nodes.ingest.answer_key import load_answer_key
    key = load_answer_key(key_path)

    records = _results(folder)
    done = [c for c in alerts if c in key and (records.get(c) or {}).get("council")]
    cases = []
    # Shown in case order, the way a scanner lists alerts by file.
    for case_id in sorted(pick_cases(done, key, seed)):
        council = records[case_id]["council"]
        validated, chair = council["validated"], council["review"]
        cases.append({
            "case_id": case_id,
            "alert": alerts[case_id],
            "verdict": validated.get("verdict"),
            "validated": bool(validated.get("validated")),
            "reason": _reason(chair.get("explanation", "")),
            "proof": _proof(validated.get("citations") or chair.get("citations") or []),
            "seconds": chair.get("latency_seconds") or 0.0,
            "cost": (chair.get("usage") or {}).get("cost") or 0.0,
            "real": key[case_id]["vulnerable"],
        })

    scan_path = Path(scan or config.RECORDED_SCAN)
    scan_alerts = (len(json.loads(scan_path.read_text(encoding="utf-8")).get("results", []))
                   if scan_path.is_file() else None)
    whole = config.EVIDENCE_DIR / "whole_system" / f"{run}.json"
    projection = None
    if whole.is_file():
        result = json.loads(whole.read_text(encoding="utf-8"))["result"]
        alone, system = result["semgrep_alone"], result["whole_system"]
        projection = {"flagged": alone["tp"] + alone["fp"], "false_alarms": alone["fp"],
                      "left": system["kept_safe"], "types": len(result.get("per_cwe", {}))}
    return {"run": run, "finished_at": (manifest.get("finished_at") or "")[:10],
            "test_cases": len(key), "scan_alerts": scan_alerts, "projection": projection,
            "cases": cases}


# --- rendering --------------------------------------------------------------

def _short(case_id: str) -> str:
    return case_id.replace("BenchmarkTest", "Test")


def _wait(console: Console, pace: float, step: bool, message: str = "") -> None:
    """Between scenes: Enter in step mode (the narrator sets the pace), else a short pause."""
    if step:
        console.input(Text(f"  {message or 'Enter to continue'} ▸ ", style="dim"))
    elif pace > 0:
        time.sleep(pace * 2)


def _scene_scan(demo: dict) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()
    grid.add_row("CODE", f"OWASP Benchmark v1.2 · {demo['test_cases']:,} Java web-app test cases")
    grid.add_row("  ↓", Text("Semgrep, an industry-standard scanner (recorded scan, rules p/java)", style="dim"))
    alerts = f"{demo['scan_alerts']:,} alerts raised" if demo["scan_alerts"] else "alerts raised"
    grid.add_row("ALERTS", alerts)
    projection = demo["projection"]
    if projection:
        share = projection["false_alarms"] / projection["flagged"]
        grid.add_row("", Text(f"For the {projection['types']} bug types we tested: {projection['flagged']:,} "
                              f"flagged, {projection['false_alarms']} of them false alarms "
                              f"(about {round(share * 10)} in 10)", style="yellow"))
    grid.add_row("", "")
    grid.add_row("DEMO", f"{len(demo['cases'])} of these alerts, from our final test")
    return Panel(grid, title="1  The code and the scanner", title_align="left", border_style="cyan",
                 padding=(0, 1))


def _scene_inbox(demo: dict) -> Panel:
    table = Table(box=None, padding=(0, 2), show_header=False)
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True, style="bold")
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True, style="dim")
    for case in demo["cases"]:
        alert = case["alert"]
        table.add_row(Text("⚠", style="yellow"), case["case_id"], CWE_NAMES.get(alert["cwe"], alert["cwe"]),
                      f"line {alert['start_line']}")
    note = Text("\nTo a developer they all look alike. Each one means opening the code and tracing "
                "the input by hand.", style="dim")
    return Panel(Group(table, note), title=f"2  {len(demo['cases'])} alerts to investigate: which are real?",
                 title_align="left", border_style="yellow", padding=(0, 1))


def _decision_line(index: int, total: int, case: dict) -> Text:
    mark, label, style = VERDICT_LINE.get(case["verdict"], ("?", str(case["verdict"]).upper(), "bold"))
    line = Text(f"  [{index:>2}/{total}] ")
    line.append(f"{case['case_id']:<20}", style="bold")
    line.append(f"{CWE_NAMES.get(case['alert']['cwe'], case['alert']['cwe']):<22}")
    line.append(f"{mark} {label:<20}", style=style)
    line.append(f"{case['seconds']:5.1f} s", style="dim")
    return line


def _scene_result(demo: dict) -> Panel:
    cases = demo["cases"]
    real = [c for c in cases if c["verdict"] == "true_positive"]
    closed = [c for c in cases if c["verdict"] == "false_positive"]
    person = [c for c in cases if c["verdict"] not in ("true_positive", "false_positive")]
    right = sum((c["verdict"] == "true_positive") == c["real"] and c["verdict"] != "human_review"
                for c in cases)

    def correct(case) -> Text:
        if case["verdict"] == "human_review":
            return Text("·", style="yellow")
        ok = (case["verdict"] == "true_positive") == case["real"]
        return Text("✓", style="bold green") if ok else Text("✗", style="bold red")

    head = Text()
    head.append(f"{len(cases)} alerts → ", style="bold")
    head.append(f"{len(cases) - len(person)} decided automatically", style="bold")
    head.append(" · ")
    head.append(f"{len(person)} need a person", style="bold yellow" if person else "bold green")

    fix = Table(box=None, padding=(0, 1), show_header=False, expand=True)
    for column in ("", "case", "type", "evidence", "ok"):
        fix.add_column(no_wrap=True, overflow="ellipsis", ratio=1 if column == "evidence" else None)
    for case in real:
        proof = case["proof"]
        evidence = (Text(f"L{proof['line']}  ", style="dim") + Text(" ".join(proof["quote"].split()), style="red")
                    if proof else Text(case["reason"]))
        fix.add_row(Text("●", style="red"), _short(case["case_id"]),
                    CWE_NAMES.get(case["alert"]["cwe"], ""), evidence, correct(case))

    shut = Table(box=None, padding=(0, 1), show_header=False, expand=True)
    for column in ("", "case", "type", "reason", "ok"):          # reasons wrap: they must be read whole
        shut.add_column(no_wrap=column != "reason", ratio=1 if column == "reason" else None)
    for case in closed:
        shut.add_row(Text("○", style="green"), _short(case["case_id"]),
                     CWE_NAMES.get(case["alert"]["cwe"], ""), Text(case["reason"], style="green"), correct(case))

    parts = [head, Text(""),
             Text(f"● TO FIX: {len(real)} confirmed vulnerabilit{'y' if len(real) == 1 else 'ies'}",
                  style="bold red") + Text("   each with the line that proves it", style="dim"),
             fix, Text(""),
             Text(f"○ CLOSED: {len(closed)} false alarm{'' if len(closed) == 1 else 's'}", style="bold green")
             + Text("   each with the reason", style="dim"),
             shut]
    if person:
        rows = Table(box=None, padding=(0, 1), show_header=False)
        for case in person:
            rows.add_row(Text("◐", style="yellow"), _short(case["case_id"]), case["reason"])
        parts += [Text(""), Text(f"◐ FOR A PERSON: {len(person)}", style="bold yellow"), rows]
    seconds = sum(c["seconds"] for c in cases)
    cost = sum(c["cost"] for c in cases)
    parts += [Text(""),
              Text(f"✓ = matches the OWASP answer key ({right} of {len(cases)})   ·   recorded model time "
                   f"{int(seconds // 60)} min {int(seconds % 60):02d} s, US${cost:.2f} for all "
                   f"{len(cases)}", style="dim")]
    return Panel(Group(*parts), title="4  The developer's new list", title_align="left",
                 border_style="bold", padding=(0, 1))


def _scene_bridge(demo: dict) -> Text | None:
    projection = demo["projection"]
    if not projection:
        return None
    line = Text("  Projected over the whole benchmark for the ")
    line.append(f"{projection['types']} tested bug types", style="bold")
    line.append(": ")
    line.append(f"{projection['false_alarms']} false alarms → about {round(projection['left'])}", style="bold green")
    line.append("\n  (the final test's removal rate per type, applied to Semgrep's results)", style="dim")
    return line


def render(demo: dict, console: Console, pace: float = 0.0, step: bool = False) -> None:
    """The whole demo. ``pace``: seconds per alert while reviewing; ``step``: wait for Enter between scenes."""
    console.print(_scene_scan(demo))
    _wait(console, pace, step, "Enter: the alerts")
    console.print(_scene_inbox(demo))
    _wait(console, pace, step, "Enter: run TriageBot")

    cases = demo["cases"]
    console.print(Text(f" 3  TriageBot reviewing {len(cases)} alerts ", style="bold black on bright_white")
                  + Text(f"   recorded run {demo['run']} ({demo['finished_at']})"
                         f"{', sped up' if pace > 0 else ''}", style="dim"))
    console.print(Text("    each alert: evidence → Analyst ∥ Skeptic → Chair → Validator", style="dim"))
    for index, case in enumerate(cases, 1):
        if pace > 0:
            with console.status(f"[dim][{index:>2}/{len(cases)}] {case['case_id']}  "
                                f"Analyst ∥ Skeptic → Chair → Validator…[/dim]"):
                time.sleep(pace)
        console.print(_decision_line(index, len(cases), case))
    _wait(console, pace, step, "Enter: the result")

    console.print()
    show_result(demo, console)


def show_result(demo: dict, console: Console) -> None:
    """Scenes 4 and 5 only: the developer's new list and the bridge to the findings (the slide image)."""
    console.print(_scene_result(demo))
    bridge = _scene_bridge(demo)
    if bridge:
        console.print(bridge)
