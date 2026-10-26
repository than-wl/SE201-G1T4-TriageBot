"""TriageBot entry point: one engine, two front doors.

Interactive menu (no arguments), from the repository root:
    python -m triagebot

    1  Scanner baseline   How good is Semgrep alone? Scored against the OWASP answer key.
    2  Triage one alert   One finding through the whole pipeline, every stage shown.
    3  Evaluate a sample  The checkpoint sample through each configuration, scored.
    q  Quit

The menu starts with the setup check (triagebot/check.py) and, if the
OWASP Benchmark is missing, offers to clone it (only on an explicit "y").
Option 1 re-runs the check and refuses while a required item is MISSING;
it then asks whether to use the current scan or re-run Semgrep, and
afterwards offers the technical details.

Non-interactive subcommands (same functions as the menu options):
    python -m triagebot check [--no-fail]
    python -m triagebot baseline [--semgrep PATH] [--answer-key PATH] [--out DIR] [--rescan] [--details]
                                 [--export-svg PATH]
    python -m triagebot triage --case BenchmarkTestNNNNN [--mode single|council]
    python -m triagebot evaluate [--sample PATH] [--mode single,council]

baseline: runs the ingest stage (triagebot.nodes.ingest.run.build), writes
the same files to --out (default Context/tmp/checkpoint/), and shows the
scanner-baseline screen: scan provenance, CWE-matched headline numbers, a
table by vulnerability type, what this means for TriageBot (noise, recall
ceiling, blind spots) and the checkpoint test set. The scan is the local
re-scan if present, else the committed recorded scan (config.effective_scan).
--rescan re-runs Semgrep first, always into config.LOCAL_SCAN, keeping the
previous local file as semgrep-owasp.previous.json and falling back to the
current scan if it fails. --details adds the file-matched comparison, CWE
mismatch pairs, ingest counts and the files written. --export-svg also
saves the screen as an SVG (README screenshot).

triage and evaluate run the connected review pipeline. They require an
OpenRouter API key and therefore make paid model calls.

check: prints the setup table; exit code 1 while a required item is MISSING
(0 with --no-fail, for CI, where the Benchmark is never cloned).

Exit codes: 0 success, 1 missing or unreadable input.

All output goes through rich; tests swap `console` and `err_console` for
fixed-width, colourless consoles.
"""

import sys

# Runs before anything else, so this file must stay parseable by Python 3.8
# (tests/test_cli.py checks it); the rest of TriageBot needs 3.10.
if sys.version_info < (3, 10):
    sys.exit("TriageBot needs Python 3.10 or newer (you have %d.%d). Install it from python.org or with "
             "`brew install python@3.12` on macOS, then recreate .venv." % tuple(sys.version_info[:2]))

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess

try:
    from rich import box
    from rich.console import Console
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:
    from triagebot import check as _check          # standard library only
    if __name__ == "__main__" and sys.argv[1:2] == ["check"]:
        code = _check.print_plain()
        sys.exit(0 if "--no-fail" in sys.argv else code)
    sys.exit(f"TriageBot needs its Python environment. Activate .venv ({_check.activate_command()}; "
             f"the prompt then shows \"(.venv)\") and run: pip install -r requirements.txt   "
             f"(see README, Quick start).")

from triagebot import check, config, pipeline
from triagebot.nodes.ingest import run
from triagebot.nodes.score import evaluate as scoring

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

BANNER = "TriageBot: evidence-grounded triage of SAST alerts (SE201 G1T4)"
OPTIONS = (
    ("1", "Scanner baseline", "How good is Semgrep alone? Scored against the OWASP answer key.", True),
    ("2", "Triage one alert", "One finding through the whole pipeline, every stage shown.", True),
    ("3", "Evaluate a sample", "The checkpoint sample through each configuration, scored.", True),
)
PROMPT = "Choose 1, 2, 3 or q: "
REVIEW_MODES = ("single", "council")

SEMGREP_RULESET = "p/java"
ANSWER_KEY_NAME = "OWASP Benchmark v1.2 answer key"
INSTALL_SEMGREP = "pip install -r requirements.txt"
SETUP_HINT = "run python -m triagebot check for the fix"
CLONE_PROMPT = "Clone the OWASP Benchmark now? (about 100 MB) \\[y/N]: "
SVG_WIDTH = 110                # columns of the recorded screen

CATEGORY_NAMES = {
    "cmdi": "Command injection",
    "crypto": "Weak encryption",
    "hash": "Weak hashing",
    "ldapi": "LDAP injection",
    "pathtraver": "Path traversal",
    "securecookie": "Insecure cookie",
    "sqli": "SQL injection",
    "trustbound": "Trust boundary violation",
    "weakrand": "Weak randomness",
    "xpathi": "XPath injection",
    "xss": "Cross-site scripting",
}
DASH = "–"


def _fail(message):
    err_console.print(Text("Error: ", style="bold red") + Text(message))
    return 1


def _pct(value):
    return DASH if value is None else f"{value:.1%}"


def _plural(n, word, plural=None):
    return f"{n:,} {word if n == 1 else plural or word + 's'}"


def _name(category):
    return CATEGORY_NAMES.get(category, category)


def _short(path) -> str:
    """Path relative to the working directory when it is inside it."""
    path = Path(path)
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def _local_time(moment: datetime) -> str:
    return moment.astimezone().strftime("%d %b %Y, %H:%M")


def scan_time(path) -> str | None:
    """When the scan ran (local time), or None if the file is absent.

    The recorded scan's date is fixed in config; any other file uses its
    modification time.
    """
    path = Path(path)
    if not path.is_file():
        return None
    recorded = config.recorded_scan_date(path)
    return _local_time(datetime.fromisoformat(recorded) if recorded
                       else datetime.fromtimestamp(path.stat().st_mtime))


def _section(title):
    console.print()
    console.print(Rule(Text(title, style="bold"), align="left", style="dim"))


# --- re-scan -------------------------------------------------------------

def _semgrep_exe() -> Path | None:
    """Semgrep next to this Python, else on PATH; None if not installed."""
    return check.semgrep_exe()


def _scan_failed(detail, partial) -> bool:
    lines = (detail or "").strip().splitlines()
    console.print(Text("The Semgrep scan did not complete", style="yellow")
                  + Text(f": {lines[-1]}" if lines else "."))
    partial.unlink(missing_ok=True)
    return False


def rescan() -> bool:
    """Re-run Semgrep into config.LOCAL_SCAN (git-ignored); True on success.

    Never touches the committed recorded scan. On any failure the local
    file is left untouched and False is returned. A previous local file is
    copied to <stem>.previous.json before replacing. Semgrep runs from the
    benchmark root on "src/main/java", so its paths are relative like the
    recorded scan's.
    """
    semgrep_path = Path(config.LOCAL_SCAN)
    exe = _semgrep_exe()
    if exe is None:
        console.print(f"[yellow]Semgrep is not installed.[/] Run: {INSTALL_SEMGREP}")
        return False
    if not config.BENCHMARK_ROOT or not (Path(config.BENCHMARK_ROOT) / "src/main/java").is_dir():
        console.print(f"[yellow]Benchmark source not found[/] ({SETUP_HINT}).")
        return False

    root = Path(config.BENCHMARK_ROOT)
    partial = semgrep_path.with_name(semgrep_path.name + ".partial")
    command = [str(exe), "scan", "--config", SEMGREP_RULESET, "--json",
               "--output", str(partial.resolve()), "src/main/java"]
    env = {**os.environ, "PYTHONUTF8": "1"}
    semgrep_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with console.status(f"Scanning... (Semgrep {SEMGREP_RULESET} on {_short(root / 'src/main/java')})"):
            completed = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True,
                                       encoding="utf-8", errors="replace")
    except OSError as error:
        return _scan_failed(str(error), partial)
    try:
        json.loads(partial.read_text(encoding="utf-8"))["results"]
    except (OSError, ValueError, KeyError, TypeError):
        return _scan_failed(completed.stderr or f"exit code {completed.returncode}", partial)

    if semgrep_path.is_file():
        shutil.copy2(semgrep_path, semgrep_path.with_name(f"{semgrep_path.stem}.previous.json"))
    partial.replace(semgrep_path)
    console.print(f"[green]Scan complete[/] (exit code {completed.returncode}); "
                  f"saved to {_short(semgrep_path)}")
    console.print("This re-scan is now used instead of the recorded scan. "
                  f"To go back, delete or rename {check.rel_path(semgrep_path)}.", markup=False)
    return True


# --- option 1: scanner baseline ------------------------------------------

def prepare_baseline(semgrep=None, answer_key=None, out=None, rescan_first=False) -> dict | None:
    """Optionally re-scan, then run ingest and write its files.

    semgrep: a scan file; default config.effective_scan() (local re-scan,
    else the recorded scan). A successful re-scan replaces it with
    config.LOCAL_SCAN. Returns {"outputs", "semgrep", "source",
    "answer_key", "out"}; None (after printing a friendly error) when an
    input is missing or unreadable.
    """
    semgrep = Path(semgrep or config.effective_scan()[0])
    answer_key = answer_key or config.ANSWER_KEY
    out = Path(out or config.CHECKPOINT_OUT)

    if rescan_first:
        if rescan():
            semgrep = Path(config.LOCAL_SCAN)
        elif semgrep.is_file():
            console.print(f"Using the {config.scan_source(semgrep)} from {scan_time(semgrep)} instead.")
    if not semgrep.is_file():
        _fail(f"Semgrep JSON not found: {semgrep}\n"
              f"Restore the recorded scan ({SETUP_HINT}), or pass --semgrep PATH.")
        return None
    if not answer_key or not Path(answer_key).is_file():
        where = answer_key or "unknown (BENCHMARK_ROOT unset and Context/tmp/BenchmarkJava missing)"
        _fail(f"OWASP answer key not found: {where}\n"
              f"Clone the OWASP Benchmark ({SETUP_HINT}), or pass --answer-key PATH.")
        return None
    try:
        outputs = run.build(semgrep, answer_key)
        written = run.write_outputs(outputs, out)
    except json.JSONDecodeError as error:
        _fail(f"{semgrep} is not valid JSON ({error}).\nRe-run the scan, or delete it to use the recorded scan.")
        return None
    except (OSError, ValueError, KeyError) as error:
        _fail(f"baseline failed: {error}")
        return None
    return {"outputs": outputs, "semgrep": semgrep, "source": config.scan_source(semgrep),
            "answer_key": Path(answer_key), "out": written}


def _type_table(rows: dict) -> Table:
    """One row per type (readable names, alphabetical); "All types" as the footer."""
    def cells(r):
        return (f"{r['tp'] + r['fn']:,}", f"{r['tp']:,}", f"{r['fn']:,}", f"{r['fp']:,}",
                _pct(r["precision"]), _pct(r["recall"]), _pct(r["f1"]))

    table = Table(title="By vulnerability type", title_justify="left", title_style="bold",
                  box=box.SIMPLE, show_footer=True, footer_style="bold")
    table.add_column("Type", footer="All types", no_wrap=True)
    for column, total in zip(("Real", "Caught", "Missed", "False alarms", "Precision", "Recall", "F1"),
                             cells(rows["overall"])):
        table.add_column(column, footer=total, justify="right", no_wrap=True)
    for category in sorted((c for c in rows if c != "overall"), key=_name):
        table.add_row(_name(category), *cells(rows[category]))
    return table


def show_baseline(ctx: dict) -> None:
    """The product screen for option 1 (CWE-matched numbers only)."""
    outputs = ctx["outputs"]
    rep, base = outputs["ingest_report.json"], outputs["baseline.json"]
    sample = outputs["split.json"]["sample"]
    rows = base["modes"]["cwe"]["by_category"]
    total = rows["overall"]
    flagged, real = total["tp"] + total["fp"], total["tp"] + total["fn"]
    scanned = (_local_time(datetime.fromisoformat(rep["scan_date"]))
               if rep.get("scan_date") else "unknown time")

    console.print()
    console.print(Rule(Text("TriageBot · Scanner baseline", style="bold"), style="cyan"))
    console.print(Text("How good is the security scanner on its own, before TriageBot?", style="italic"),
                  justify="center")
    console.print()
    provenance = Table.grid(padding=(0, 2))
    provenance.add_column(style="dim")
    provenance.add_column()
    provenance.add_row("Scan", f"Semgrep {rep['semgrep_version']}, ruleset {SEMGREP_RULESET}, "
                               f"{ctx.get('source') or config.scan_source(ctx['semgrep'])} "
                               f"from {scanned} (local time), {rep['alerts']:,} alerts")
    provenance.add_row("Scored against", f"{ANSWER_KEY_NAME}, {base['answer_key']['cases']:,} test cases")
    console.print(provenance)

    _section("Headline")
    console.print(f"Semgrep raised alerts on [bold]{flagged:,}[/] test cases.")
    console.print(f"  {total['tp']:,} were real vulnerabilities and {total['fp']:,} were false alarms: "
                  f"precision [bold]{_pct(total['precision'])}[/].")
    console.print(f"  It caught {total['tp']:,} of {real:,} real vulnerabilities: "
                  f"recall [bold]{_pct(total['recall'])}[/].")
    console.print(f"  F1 [bold]{_pct(total['f1'])}[/] (balance of the two).")

    console.print()
    console.print(_type_table(rows))

    _section("What this means for TriageBot")
    noise = total["fp"] / flagged if flagged else None
    console.print(f"Noise to remove: {total['fp']:,} of {flagged:,} flagged test cases "
                  f"({_pct(noise)}) are false alarms.")
    console.print(f"Recall ceiling: TriageBot can only filter alerts, never add them, so the system can "
                  f"catch at most [bold]{_pct(total['recall'])}[/] of real vulnerabilities with this scan.")
    blind = [f"{_name(c)} (0 of {r['tp'] + r['fn']:,})" for c, r in sorted(rows.items(), key=lambda kv: _name(kv[0]))
             if c != "overall" and r["tp"] == 0 and r["tp"] + r["fn"] > 0]
    console.print(f"Blind spots (nothing caught): {', '.join(blind) if blind else 'none'}.")

    _section("Checkpoint test set")
    category = next((c for c, cwe in base["category_cwe"].items() if cwe == sample["cwe"]), None)
    label = f"{_name(category)} ({sample['cwe']})" if category else sample["cwe"]
    short = (f" (requested {sample['requested']}; only {sample['selected']} eligible)"
             if sample["shortfall"] else "")
    console.print(f"{sample['selected']} {label} test cases from the development split{short}: "
                  f"{_plural(sample['selected_vulnerable'], 'real vulnerability', 'real vulnerabilities')}, "
                  f"{_plural(sample['selected_safe'], 'false alarm')}.")

    console.print()
    footer = Text(style="dim")
    footer.append("Precision: of the test cases Semgrep flagged, the share that are real vulnerabilities.\n")
    footer.append("Recall: of the real vulnerabilities, the share Semgrep flagged.\n")
    footer.append("An alert counts only if it names the same weakness the test case targets (CWE match).\n")
    footer.append(f"Full results: {_short(ctx['out'] / 'baseline.json')}")
    console.print(footer)


def show_details(ctx: dict) -> None:
    """Technical extras: matching comparison, mismatch pairs, ingest counts, files."""
    outputs = ctx["outputs"]
    rep, base = outputs["ingest_report.json"], outputs["baseline.json"]

    _section("Technical details")
    compare = Table(title="Overall, by matching mode", title_justify="left", title_style="bold",
                    box=box.SIMPLE_HEAD, caption_justify="left",
                    caption="file-matched is the proposal's method: any alert flags the test case. "
                            "CWE-matched is the default used on the main screen.")
    compare.add_column("Mode", no_wrap=True)
    for column in ("Flagged", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1"):
        compare.add_column(column, justify="right")
    for mode, label in (("cwe", 'CWE-matched (mode "cwe")'), ("file", 'file-matched (mode "file")')):
        r = base["modes"][mode]["by_category"]["overall"]
        compare.add_row(label, f"{r['tp'] + r['fp']:,}", f"{r['tp']:,}", f"{r['fp']:,}", f"{r['fn']:,}",
                        f"{r['tn']:,}", _pct(r["precision"]), _pct(r["recall"]), _pct(r["f1"]))
    console.print(compare)

    pairs = base["cwe_mismatches"]
    shown = f"top 10 of {len(pairs)}" if len(pairs) > 10 else str(len(pairs))
    mismatch = Table(title=f"CWE mismatch pairs ({shown})", title_justify="left",
                     title_style="bold", box=box.SIMPLE_HEAD)
    for column, justify in (("Type", "left"), ("Benchmark CWE", "left"), ("Semgrep CWE", "left"),
                            ("Alerts", "right"), ("Cases", "right"), ("Cases w/o match", "right"),
                            ("Rule ids", "left")):
        mismatch.add_column(column, justify=justify, no_wrap=column in ("Type", "Rule ids"))
    for r in pairs[:10]:
        mismatch.add_row(_name(r["category"]), r["benchmark_cwe"], r["semgrep_cwe"] or "(none)",
                         f"{r['alerts']:,}", f"{r['cases']:,}", f"{r['cases_without_matching_alert']:,}",
                         ", ".join(f"{rule.rsplit('.', 1)[-1]} ({n})" for rule, n in r["rule_ids"].items()))
    console.print()
    console.print(mismatch)

    counts = Table(title="Ingest counts", title_justify="left", title_style="bold", box=box.SIMPLE_HEAD)
    counts.add_column("Count")
    counts.add_column("Value", justify="right")
    for label, value in (
            ("Semgrep findings", rep["total_findings"]),
            ("  in benchmark test files", rep["test_file_findings"]),
            ("  helper-file findings dropped", rep["helper_file_findings_dropped"]["count"]),
            ("  unmapped paths", rep["unmapped_paths"]["count"]),
            ("Exact duplicates collapsed", rep["exact_duplicates_collapsed"]),
            ("Alerts", rep["alerts"]),
            ("  without a CWE", rep["alerts_without_cwe"]),
            ("  with several CWEs (first kept)", rep["alerts_with_multiple_cwes"]["count"]),
            ("Test cases with at least one alert", rep["cases_with_alerts"]),
            ("Test cases with no alert", base["cases_without_alerts"]),
            ("Semgrep errors", rep["semgrep_errors"])):
        counts.add_row(label, f"{value:,}")
    console.print()
    console.print(counts)

    console.print()
    console.print(Text("Files written", style="bold"))
    console.print(f"  Semgrep input: {_short(ctx['semgrep'])}")
    console.print(f"  Answer key:    {_short(ctx['answer_key'])}")
    for name in outputs:
        console.print(f"  Written:       {_short(ctx['out'] / name)}")


def baseline(semgrep=None, answer_key=None, out=None, rescan_first=False, details=False,
             export_svg=None) -> int:
    """`baseline` subcommand: prepare, show the screen, optionally the details.

    export_svg: also record the screen (fixed width, colour) and save it there.
    """
    global console
    ctx = prepare_baseline(semgrep, answer_key, out, rescan_first=rescan_first)
    if ctx is None:
        return 1
    shown = console
    if export_svg:
        console = Console(record=True, width=SVG_WIDTH, force_terminal=True, color_system="truecolor",
                          highlight=False, file=shown.file)
    try:
        show_baseline(ctx)
        if details:
            show_details(ctx)
        if export_svg:
            target = Path(export_svg)
            target.parent.mkdir(parents=True, exist_ok=True)
            console.save_svg(str(target), title="TriageBot · Scanner baseline")
    finally:
        console = shown
    if export_svg:
        console.print(f"Saved the screen to {_short(export_svg)}")
    return 0


# --- setup check ------------------------------------------------------------

STATUS_STYLE = {check.OK: "green", check.MISSING: "bold red", check.WARNING: "yellow"}


def show_check(checks) -> None:
    table = Table(title="Setup check", title_justify="left", title_style="bold", box=box.SIMPLE_HEAD)
    table.add_column("Check", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail")
    for c in checks:
        table.add_row(c.name, Text(c.status, style=STATUS_STYLE[c.status]), c.detail)
    console.print(table)
    fixes = [c for c in checks if c.status != check.OK and c.fix]
    for c in fixes:
        label = "Optional:" if c.status == check.WARNING else "To fix:"
        console.print(Text(f"{label} {c.name}", style="bold"))
        for line in c.fix.splitlines():
            console.print(f"  {line}", markup=False)
    if fixes:
        console.print()


def setup_check(no_fail=False) -> int:
    """`check` subcommand: the table; exit code 1 while a required item is MISSING."""
    checks = check.run_checks()
    show_check(checks)
    return 0 if no_fail or not check.blocking(checks) else 1


def clone_benchmark(target=None) -> bool:
    """git clone the benchmark and check out the pinned commit; True on success."""
    target = Path(target or check.benchmark_dir())
    try:
        with console.status(f"Cloning the OWASP Benchmark into {_short(target)}..."):
            for command in check.clone_commands(target):
                done = subprocess.run(command, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace")
                if done.returncode != 0:
                    lines = (done.stderr or "").strip().splitlines()
                    console.print(Text("Clone failed", style="yellow")
                                  + Text(f": {lines[-1]}" if lines else f" (exit code {done.returncode})."))
                    return False
    except OSError as error:
        console.print(f"[yellow]Could not run git[/] ({error}). Install Git from https://git-scm.com/ "
                      "and try again.")
        return False
    config.BENCHMARK_ROOT = str(target)
    config.ANSWER_KEY = target / check.ANSWER_KEY_NAME
    console.print(f"[green]Cloned[/] the benchmark at commit {config.BENCHMARK_COMMIT[:12]} into {_short(target)}")
    return True


# --- options 2 and 3: connected review pipeline -----------------------------

def _sample_alerts(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    alerts = data.get("alerts") if isinstance(data, dict) else data
    if not isinstance(alerts, list) or not all(isinstance(alert, dict) for alert in alerts):
        raise ValueError(f"{path}: expected a list of normalised alerts")
    return alerts


def triage_one(case=None, mode="single", sample=None, out=None) -> int:
    """Menu option 2 / `triage`: one saved alert through the pipeline."""
    sample = Path(sample or config.CHECKPOINT_OUT / "selected_alerts.json")
    out = Path(out or config.CHECKPOINT_OUT)
    try:
        alerts = _sample_alerts(sample)
        matches = [alert for alert in alerts if alert.get("case_id") == case]
        if not matches:
            return _fail(f"{case} is not in {_short(sample)}; run the baseline or choose a sampled case")
        result = pipeline.triage(matches[0], mode)
        out.mkdir(parents=True, exist_ok=True)
        target = out / f"triage-{case}-{mode}.json"
        target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return _fail(str(error))
    final = result["validated"]
    console.print(f"[bold]{case}[/] via {mode}: [bold]{final['verdict']}[/] "
                  f"(validation {'passed' if final['validated'] else 'sent to human review'})")
    console.print(f"Saved: {_short(target)}")
    return 0


def evaluate_sample(sample=None, modes=REVIEW_MODES, out=None, answer_key=None) -> int:
    """Menu option 3 / `evaluate`: run and score the checkpoint sample."""
    sample = Path(sample or config.CHECKPOINT_OUT / "selected_alerts.json")
    out = Path(out or config.CHECKPOINT_OUT)
    answer_key = Path(answer_key or config.ANSWER_KEY or "")
    if not answer_key.is_file():
        return _fail(f"answer key not found: {answer_key}")
    try:
        alerts = _sample_alerts(sample)
        configurations = pipeline.run_sample(alerts, tuple(modes), out)
        configs = {name: (data["results"], data.get("model"))
                   for name, data in configurations.items()}
        report = scoring.evaluate(
            [alert["case_id"] for alert in alerts], scoring.load_labels(answer_key), configs)
        out.mkdir(parents=True, exist_ok=True)
        target = out / "evaluation.json"
        target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return _fail(str(error))
    console.print(scoring.markdown_table(report), markup=False)
    console.print(f"\nReport: {_short(target)}")
    return 0


# --- opt-in durable council sessions (Phase 2; no human-review workflow) ------

def _save_council_result(thread_id, result, out):
    out = Path(out or config.CHECKPOINT_OUT)
    out.mkdir(parents=True, exist_ok=True)
    target = out / f"council-{thread_id}.json"
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    console.print(f"Saved: {_short(target)}", markup=False)


def council_start(case, sample=None, db=None, out=None, benchmark_root=None):
    """Explicitly start a NEW paid council session and print its ID first."""
    from triagebot.checkpoints import create_council_run, resume_council_run
    import sqlite3
    try:
        alerts = _sample_alerts(Path(sample or config.CHECKPOINT_OUT / "selected_alerts.json"))
        matches = [alert for alert in alerts if alert.get("case_id") == case]
        if not matches:
            return _fail(f"{case} is not in the selected sample")
        thread_id = create_council_run(matches[0], db, benchmark_root=benchmark_root)
        console.print(f"Council thread: {thread_id}", markup=False)
        console.file.flush()
        result = resume_council_run(thread_id, db, allow_replay=True,
                                    benchmark_root=benchmark_root)
        _save_council_result(thread_id, result, out)
    except (OSError, ValueError, KeyError, RuntimeError, sqlite3.Error) as error:
        return _fail(str(error))
    return 0


def council_status(thread_id, db=None):
    """Inspect saved metadata without creating a model client or executing nodes."""
    from triagebot.checkpoints import inspect_council_run
    import sqlite3
    try:
        status = inspect_council_run(thread_id, db)
        # Source evidence remains local in SQLite, not dumped by the status command.
        status.pop("result", None)
        console.print(json.dumps(status, indent=2, sort_keys=True), markup=False)
    except (OSError, ValueError, KeyError, RuntimeError, sqlite3.Error) as error:
        return _fail(str(error))
    return 0


def council_resume(thread_id, db=None, out=None, benchmark_root=None, allow_replay=False):
    """Resume SAME thread; acknowledge possible duplicate charges after a crash."""
    from triagebot.checkpoints import resume_council_run
    import sqlite3
    try:
        result = resume_council_run(thread_id, db, allow_replay=allow_replay,
                                    benchmark_root=benchmark_root)
        _save_council_result(thread_id, result, out)
    except (OSError, ValueError, KeyError, RuntimeError, sqlite3.Error) as error:
        return _fail(str(error))
    return 0


# --- front door 1: interactive menu ----------------------------------------

class _Quit(Exception):
    """End of input at any prompt."""


def _ask(prompt, lower=True) -> str:
    try:
        answer = console.input(prompt).strip()
        return answer.lower() if lower else answer
    except (EOFError, KeyboardInterrupt):
        console.print()
        raise _Quit from None


def show_menu() -> None:
    console.print()
    console.print(Text("TriageBot", style="bold cyan") + Text("  evidence-grounded triage of SAST alerts "
                                                              "(SE201 G1T4)", style="dim"))
    console.print()
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", justify="right")
    grid.add_column()
    grid.add_column()
    for key, title, description, available in OPTIONS:
        style = "" if available else "dim"
        grid.add_row(f"  {key}", Text(title, style=style),
                     Text(description, style=style) + (Text("") if available else
                                                       Text("  (coming soon)", style="yellow")))
    grid.add_row("  q", "Quit", "")
    console.print(grid)
    console.print()


def _menu_check(show_when_ready=True) -> bool:
    """Run the setup check (offering to clone a missing benchmark); True if nothing blocks."""
    checks = check.run_checks()
    if show_when_ready or check.blocking(checks):
        show_check(checks)
    if check.benchmark_missing(checks) and _ask(CLONE_PROMPT) in ("y", "yes"):
        if clone_benchmark():
            checks = check.run_checks()
            show_check(checks)
    return not check.blocking(checks)


def _menu_baseline(semgrep, answer_key, out) -> None:
    if not _menu_check(show_when_ready=False):
        console.print("[yellow]Option 1 needs the items marked MISSING above.[/] "
                      "Run the commands shown, then choose 1 again.")
        _ask("Press Enter to return to the menu")
        return
    path = Path(semgrep or config.effective_scan()[0])
    when = scan_time(path)
    use = (f"use the {config.scan_source(path)} from {when}" if when
           else "use the saved scan (none found)")
    if _semgrep_exe():
        choice = _ask(f"[bold]\\[Enter][/] {use}   [bold]r[/] = re-run Semgrep now "
                      "(takes a few minutes, needs internet): ")
    else:
        _ask(f"[bold]\\[Enter][/] {use}   (re-scan unavailable: Semgrep not installed): ")
        choice = ""
    ctx = prepare_baseline(semgrep, answer_key, out, rescan_first=choice == "r")
    if ctx is None:
        _ask("Press Enter to return to the menu")
        return
    show_baseline(ctx)
    console.print()
    if _ask("[bold]d[/] = show technical details   [bold]\\[Enter][/] = back to menu: ") == "d":
        show_details(ctx)
        console.print()
        _ask("Press Enter to return to the menu")


def _menu_triage(out) -> None:
    if not _menu_check(show_when_ready=False):
        console.print("[yellow]Triage needs the items marked MISSING above.[/]")
        _ask("Press Enter to return to the menu")
        return
    case = _ask("Case ID (for example BenchmarkTest00001): ", lower=False)
    choice = _ask("[bold]s[/] = single agent   [bold]c[/] = council   [bold]\\[Enter][/] = single: ")
    mode = "council" if choice in ("c", "council") else "single"
    triage_one(case, mode, None, out)
    console.print()
    _ask("Press Enter to return to the menu")


def _menu_evaluate(answer_key, out) -> None:
    if not _menu_check(show_when_ready=False):
        console.print("[yellow]Evaluation needs the items marked MISSING above.[/]")
        _ask("Press Enter to return to the menu")
        return
    console.print("[yellow]This paid run uses up to 4 model calls per finding "
                  "(1 single-agent + 3 council calls).[/]")
    if _ask("Continue? \\[y/N]: ") in ("y", "yes"):
        evaluate_sample(None, REVIEW_MODES, out, answer_key)
    console.print()
    _ask("Press Enter to return to the menu")


def menu(semgrep=None, answer_key=None, out=None) -> int:
    """Loop until q (or end of input)."""
    actions = {
        "1": lambda: _menu_baseline(semgrep, answer_key, out),
        "2": lambda: _menu_triage(out),
        "3": lambda: _menu_evaluate(answer_key, out),
    }
    try:
        _menu_check()
        show_menu()
        while True:
            choice = _ask(PROMPT)
            if choice in ("q", "quit", "exit"):
                return 0
            if choice not in actions:
                console.print(f"Unknown option {choice!r}.", markup=False)
                continue
            actions[choice]()
            show_menu()
    except _Quit:
        return 0


# --- front door 2: subcommands ----------------------------------------------

def _modes(text):
    modes = tuple(m.strip() for m in text.split(",") if m.strip())
    bad = [m for m in modes if m not in REVIEW_MODES]
    if bad or not modes:
        raise argparse.ArgumentTypeError(f"modes must be from {', '.join(REVIEW_MODES)}, got {text!r}")
    return modes


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m triagebot", description=BANNER,
                                epilog="With no subcommand, opens the interactive menu.")
    sub = p.add_subparsers(dest="command")

    c = sub.add_parser("check", help="is this machine ready? Python, venv, rich, benchmark, scan, Semgrep")
    c.add_argument("--no-fail", action="store_true",
                   help="exit 0 even when something is MISSING (CI: report without failing the job)")

    b = sub.add_parser("baseline", help="menu option 1: score Semgrep alone against the answer key")
    b.add_argument("--semgrep", help=f"Semgrep JSON (default: {_short(config.LOCAL_SCAN)} if present, "
                                     f"else the recorded scan {_short(config.RECORDED_SCAN)})")
    b.add_argument("--answer-key", help="expectedresults-1.2.csv (default: under BENCHMARK_ROOT)")
    b.add_argument("--out", help=f"output directory (default {config.CHECKPOINT_OUT})")
    b.add_argument("--rescan", action="store_true",
                   help=f"re-run Semgrep first into {_short(config.LOCAL_SCAN)} (a few minutes, needs "
                        f"internet and {INSTALL_SEMGREP}); falls back to the current scan")
    b.add_argument("--details", action="store_true",
                   help="also show matching comparison, CWE mismatch pairs, ingest counts and files written")
    b.add_argument("--export-svg", metavar="PATH", help="also save the screen as an SVG image")

    t = sub.add_parser("triage", help="menu option 2: one alert through the pipeline")
    t.add_argument("--case", required=True, help="BenchmarkTestNNNNN")
    t.add_argument("--mode", choices=REVIEW_MODES, default="single")
    t.add_argument("--sample", help="selected_alerts.json (default: under the checkpoint output folder)")
    t.add_argument("--out", help=f"output directory (default {config.CHECKPOINT_OUT})")

    e = sub.add_parser("evaluate", help="menu option 3: evaluate the checkpoint sample")
    e.add_argument("--sample", help="selected_alerts.json (default: under --out of baseline)")
    e.add_argument("--mode", type=_modes, default=REVIEW_MODES, help="comma-separated: single,council")
    e.add_argument("--out", help=f"output directory (default {config.CHECKPOINT_OUT})")
    e.add_argument("--answer-key", help="expectedresults-1.2.csv (default: under BENCHMARK_ROOT)")
    cs = sub.add_parser("council-start", help="NEW paid council run with local SQLite checkpoints")
    cs.add_argument("--case", required=True, help="case from selected_alerts.json")
    cs.add_argument("--sample", help="normalised selected-alerts file")
    cs.add_argument("--db", help="local SQLite file (default .triagebot/checkpoints.sqlite)")
    cs.add_argument("--out", help="directory for the completed public result JSON")
    cs.add_argument("--benchmark-root", help="source checkout (default BENCHMARK_ROOT)")

    ci = sub.add_parser("council-status", help="inspect a saved council thread; no model calls")
    ci.add_argument("--thread-id", required=True, help="UUID printed when the run was created")
    ci.add_argument("--db", help="local SQLite file")

    cr = sub.add_parser("council-resume", help="resume a saved thread; may repeat uncommitted paid calls")
    cr.add_argument("--thread-id", required=True, help="UUID printed when the run was created")
    cr.add_argument("--db", help="local SQLite file")
    cr.add_argument("--out", help="directory for the completed public result JSON")
    cr.add_argument("--benchmark-root", help="source checkout (default BENCHMARK_ROOT)")
    cr.add_argument("--allow-replay", action="store_true",
                    help="acknowledge possible duplicate model charges for an incomplete run")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.command == "check":
        return setup_check(args.no_fail)
    if args.command == "baseline":
        return baseline(args.semgrep, args.answer_key, args.out, args.rescan, args.details, args.export_svg)
    if args.command == "triage":
        return triage_one(args.case, args.mode, args.sample, args.out)
    if args.command == "evaluate":
        return evaluate_sample(args.sample, args.mode, args.out, args.answer_key)
    if args.command == "council-start":
        return council_start(args.case, args.sample, args.db, args.out, args.benchmark_root)
    if args.command == "council-status":
        return council_status(args.thread_id, args.db)
    if args.command == "council-resume":
        return council_resume(args.thread_id, args.db, args.out, args.benchmark_root, args.allow_replay)
    return menu()


if __name__ == "__main__":
    sys.exit(main())
