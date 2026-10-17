"""TriageBot entry point: one engine, two front doors.

Interactive menu (no arguments), from the repository root:
    py -m triagebot

    1  Scanner baseline   How good is Semgrep alone? Scored against the OWASP answer key.
    2  Triage one alert   One finding through the whole pipeline, every stage shown.  (coming soon)
    3  Evaluate a sample  The checkpoint sample through each configuration, scored.  (coming soon)
    q  Quit

Option 1 first asks whether to use the saved Semgrep scan or re-run
Semgrep, and afterwards offers the technical details.

Non-interactive subcommands (same functions as the menu options):
    py -m triagebot baseline [--semgrep PATH] [--answer-key PATH] [--out DIR] [--rescan] [--details]
    py -m triagebot triage --case BenchmarkTestNNNNN [--mode single|council]
    py -m triagebot evaluate [--sample PATH] [--mode single,council]

baseline: runs the ingest stage (triagebot.nodes.ingest.run.build), writes
the same files to --out (default Context/tmp/checkpoint/), and shows the
scanner-baseline screen: scan provenance, CWE-matched headline numbers, a
table by vulnerability type, what this means for TriageBot (noise, recall
ceiling, blind spots) and the checkpoint test set. --rescan re-runs Semgrep
first (README Setup, "Semgrep scan"), keeping the previous file as
semgrep-owasp.previous.json and falling back to it if the scan fails.
--details adds the file-matched comparison, CWE mismatch pairs, ingest
counts and the files written. Paths default to triagebot/config.py.

triage and evaluate are placeholders until triagebot/pipeline.py is
wired; they print a notice and exit with code 2.

Exit codes: 0 success, 1 missing or unreadable input, 2 not yet available.

All output goes through rich; tests swap `console` and `err_console` for
fixed-width, colourless consoles.
"""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

try:
    from rich import box
    from rich.console import Console
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:
    sys.exit(r"TriageBot needs its Python environment. Run it with "
             r".\.verification-venv\Scripts\python.exe -m triagebot, or activate the venv first "
             r"(see README, Setup).")

from triagebot import config
from triagebot.nodes.ingest import run

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

BANNER = "TriageBot: evidence-grounded triage of SAST alerts (SE201 G1T4)"
OPTIONS = (
    ("1", "Scanner baseline", "How good is Semgrep alone? Scored against the OWASP answer key.", True),
    ("2", "Triage one alert", "One finding through the whole pipeline, every stage shown.", False),
    ("3", "Evaluate a sample", "The checkpoint sample through each configuration, scored.", False),
)
PROMPT = "Choose 1, 2, 3 or q: "
NOT_YET = "Not yet available: the end-to-end pipeline (triagebot/pipeline.py) is being wired."
REVIEW_MODES = ("single", "council")

SEMGREP_RULESET = "p/java"
ANSWER_KEY_NAME = "OWASP Benchmark v1.2 answer key"
SETUP_SEMGREP = 'README section 4 (Setup), "Semgrep scan"'
SETUP_BENCHMARK = 'README section 4 (Setup), "OWASP Benchmark"'

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


def saved_scan_time(path) -> str | None:
    """Local modification time of the saved Semgrep JSON, or None if absent."""
    path = Path(path)
    return _local_time(datetime.fromtimestamp(path.stat().st_mtime)) if path.is_file() else None


def _section(title):
    console.print()
    console.print(Rule(Text(title, style="bold"), align="left", style="dim"))


# --- re-scan -------------------------------------------------------------

def _semgrep_exe() -> Path | None:
    """The venv's Semgrep (next to this Python), or None if not installed."""
    name = "semgrep.exe" if os.name == "nt" else "semgrep"
    exe = Path(sys.executable).with_name(name)
    return exe if exe.is_file() else None


def _scan_failed(detail, partial) -> bool:
    lines = (detail or "").strip().splitlines()
    console.print(Text("The Semgrep scan did not complete", style="yellow")
                  + Text(f": {lines[-1]}" if lines else "."))
    partial.unlink(missing_ok=True)
    return False


def rescan(semgrep_path) -> bool:
    """Re-run Semgrep into semgrep_path; True on success.

    On any failure the saved file is left untouched and False is returned.
    The previous file is copied to <stem>.previous.json before replacing.
    """
    semgrep_path = Path(semgrep_path)
    exe = _semgrep_exe()
    if exe is None:
        console.print(f"[yellow]Semgrep is not installed in this environment[/] "
                      f"(see {SETUP_SEMGREP}).")
        return False
    if not config.BENCHMARK_ROOT or not (Path(config.BENCHMARK_ROOT) / "src/main/java").is_dir():
        console.print(f"[yellow]Benchmark source not found[/] (see {SETUP_BENCHMARK}).")
        return False

    source = Path(config.BENCHMARK_ROOT) / "src" / "main" / "java"
    partial = semgrep_path.with_name(semgrep_path.name + ".partial")
    command = [str(exe), "scan", "--config", SEMGREP_RULESET, "--json",
               "--output", str(partial), str(source)]
    env = {**os.environ, "PYTHONUTF8": "1"}
    semgrep_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with console.status(f"Scanning... (Semgrep {SEMGREP_RULESET} on {source})"):
            completed = subprocess.run(command, env=env, capture_output=True, text=True,
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
    console.print(f"[green]Scan complete[/] (exit code {completed.returncode}); saved to {semgrep_path}")
    return True


# --- option 1: scanner baseline ------------------------------------------

def prepare_baseline(semgrep=None, answer_key=None, out=None, rescan_first=False) -> dict | None:
    """Optionally re-scan, then run ingest and write its files.

    Returns {"outputs", "semgrep", "answer_key", "out"}; None (after printing
    a friendly error) when an input is missing or unreadable.
    """
    semgrep = Path(semgrep or config.SEMGREP_JSON)
    answer_key = answer_key or config.ANSWER_KEY
    out = Path(out or config.CHECKPOINT_OUT)

    if rescan_first and not rescan(semgrep):
        if semgrep.is_file():
            console.print(f"Using the saved scan from {saved_scan_time(semgrep)} instead.")
    if not semgrep.is_file():
        _fail(f"Semgrep JSON not found: {semgrep}\n"
              f"Run the scan in {SETUP_SEMGREP}, or pass --semgrep PATH.")
        return None
    if not answer_key or not Path(answer_key).is_file():
        where = answer_key or "unknown (BENCHMARK_ROOT unset and Context/tmp/BenchmarkJava missing)"
        _fail(f"OWASP answer key not found: {where}\n"
              f"Clone the benchmark as in {SETUP_BENCHMARK}, or pass --answer-key PATH.")
        return None
    try:
        outputs = run.build(semgrep, answer_key)
        written = run.write_outputs(outputs, out)
    except json.JSONDecodeError as error:
        _fail(f"{semgrep} is not valid JSON ({error}).\nRe-run the scan in {SETUP_SEMGREP}.")
        return None
    except (OSError, ValueError, KeyError) as error:
        _fail(f"baseline failed: {error}")
        return None
    return {"outputs": outputs, "semgrep": semgrep, "answer_key": Path(answer_key), "out": written}


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
                               f"saved {scanned} (local time), {rep['alerts']:,} alerts")
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


def baseline(semgrep=None, answer_key=None, out=None, rescan_first=False, details=False) -> int:
    """`baseline` subcommand: prepare, show the screen, optionally the details."""
    ctx = prepare_baseline(semgrep, answer_key, out, rescan_first=rescan_first)
    if ctx is None:
        return 1
    show_baseline(ctx)
    if details:
        show_details(ctx)
    return 0


# --- options 2 and 3: placeholders (Wei Lin connects these to pipeline.py) --

def triage_one(case=None, mode="single") -> int:
    """PLACEHOLDER. Menu option 2 / `triage`: one alert through the pipeline."""
    console.print(NOT_YET)
    return 2


def evaluate_sample(sample=None, modes=REVIEW_MODES) -> int:
    """PLACEHOLDER. Menu option 3 / `evaluate`: the sample through each configuration."""
    console.print(NOT_YET)
    return 2


# --- front door 1: interactive menu ----------------------------------------

class _Quit(Exception):
    """End of input at any prompt."""


def _ask(prompt) -> str:
    try:
        return console.input(prompt).strip().lower()
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


def _menu_baseline(semgrep, answer_key, out) -> None:
    saved = saved_scan_time(semgrep or config.SEMGREP_JSON)
    use = f"use saved scan from {saved}" if saved else "use saved scan (none found)"
    choice = _ask(f"[bold]\\[Enter][/] {use}   [bold]r[/] = re-run Semgrep now "
                  "(takes a few minutes, needs internet): ")
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


def _menu_placeholder(action) -> None:
    action()
    console.print()
    _ask("Press Enter to return to the menu")


def menu(semgrep=None, answer_key=None, out=None) -> int:
    """Loop until q (or end of input). Arguments are passed to option 1."""
    actions = {
        "1": lambda: _menu_baseline(semgrep, answer_key, out),
        "2": lambda: _menu_placeholder(triage_one),
        "3": lambda: _menu_placeholder(evaluate_sample),
    }
    show_menu()
    try:
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

    b = sub.add_parser("baseline", help="menu option 1: score Semgrep alone against the answer key")
    b.add_argument("--semgrep", help=f"Semgrep JSON (default {config.SEMGREP_JSON})")
    b.add_argument("--answer-key", help="expectedresults-1.2.csv (default: under BENCHMARK_ROOT)")
    b.add_argument("--out", help=f"output directory (default {config.CHECKPOINT_OUT})")
    b.add_argument("--rescan", action="store_true",
                   help="re-run Semgrep first (a few minutes, needs internet); falls back to the saved scan")
    b.add_argument("--details", action="store_true",
                   help="also show matching comparison, CWE mismatch pairs, ingest counts and files written")

    t = sub.add_parser("triage", help="menu option 2: one alert through the pipeline (coming soon)")
    t.add_argument("--case", required=True, help="BenchmarkTestNNNNN")
    t.add_argument("--mode", choices=REVIEW_MODES, default="single")

    e = sub.add_parser("evaluate", help="menu option 3: evaluate the checkpoint sample (coming soon)")
    e.add_argument("--sample", help="selected_alerts.json (default: under --out of baseline)")
    e.add_argument("--mode", type=_modes, default=REVIEW_MODES, help="comma-separated: single,council")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.command == "baseline":
        return baseline(args.semgrep, args.answer_key, args.out, args.rescan, args.details)
    if args.command == "triage":
        return triage_one(args.case, args.mode)
    if args.command == "evaluate":
        return evaluate_sample(args.sample, args.mode)
    return menu()


if __name__ == "__main__":
    sys.exit(main())
