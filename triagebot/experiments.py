"""Experiment runner: plan, run, show and replay the steps in EXPERIMENTS.md.

The steps live in experiments/registry.json. Each step has a "before" and an
"after" side; a side either runs (a profile from triagebot/profiles.py plus
review modes) or reuses another step's saved run at no cost. Every run is
scored on one frozen case set from data/samples/ and saved to

    evidence/experiments/<step>-<side>[-repeat-N]/
        results.jsonl              one line per finished case (written after every case)
        B-single-agent.json        evaluator-format results, as applicable
        C-council.json
        D-validated-council.json
        evaluation.json            scoring.evaluate() over the run's cases
        evaluation_by_cwe.json     final_report.build(): overall and per CWE
        run_manifest.json          what produced the run (profile, case set, model, Git, cost)
        report.md                  a short plain-English report

Paid work happens only in execute(); the caller (the CLI) prints the plan's
cost estimate and asks for confirmation first. An interrupted run resumes from
results.jsonl without repeating finished cases. show_table() is offline and
needs neither an API key nor the answer key; replay() re-scores the saved
outputs against the answer key and makes no model calls.

The answer key is read only in finalize() and replay(), after the model calls,
and only evaluation-side files (evaluation*.json, report.md) carry scores.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

from triagebot import config, profiles
from triagebot.nodes.ingest import eval_sets

MODES = ("single", "council")
CONFIGURATIONS = {"single": ("B-single-agent",), "council": ("C-council", "D-validated-council")}
RESULTS_LOG = "results.jsonl"
MANIFEST = "run_manifest.json"
EVALUATION = "evaluation.json"
EVALUATION_BY_CWE = "evaluation_by_cwe.json"
REPORT = "report.md"
FAILED_CALL_PREFIX = "Model call failed"     # report.failure() explanation

# (label, key, kind) for the before/after table; kind formats the value.
METRICS = (
    ("Precision", "precision", "pct"),
    ("Recall", "recall", "pct"),
    ("F1", "f1", "pct"),
    ("Real vulnerabilities dismissed", "genuine_dismissed", "of_genuine"),
    ("False alarms removed", "fp_removed", "of_fp"),
    ("Sent to a human", "human_review", "of_all"),
    ("Invalid answers", "invalid_outputs", "int"),
    ("Mean latency (s)", "usage.latency_mean_seconds", "float"),
    ("Total cost (US$)", "usage.cost_total", "money"),
    ("Prompt tokens", "usage.prompt_tokens_total", "int"),
)


class ExperimentError(ValueError):
    """The request cannot be carried out; the message says why and what to do."""


# --- registry -----------------------------------------------------------------------

def load_registry(path=None) -> list[dict]:
    path = Path(path or config.EXPERIMENT_REGISTRY)
    steps = json.loads(path.read_text(encoding="utf-8"))["steps"]
    for step in steps:
        for side in ("before", "after"):
            spec = step.get(side)
            if spec and "reuse" not in spec:
                profiles.get(spec["profile"])
                if not spec["modes"] or set(spec["modes"]) - set(MODES):
                    raise ExperimentError(f"step {step['id']} {side}: bad modes {spec['modes']}")
    return steps


def get_step(step_id, registry=None) -> dict:
    steps = registry if registry is not None else load_registry()
    for step in steps:
        if step["id"] == str(step_id):
            return step
    raise ExperimentError(f"unknown step {step_id!r}; choose from {', '.join(s['id'] for s in steps)}")


def run_name(step_id, side, repeat=1) -> str:
    return f"{step_id}-{side}" + (f"-repeat-{repeat}" if repeat > 1 else "")


def runs_for(step) -> dict[str, list[str]]:
    """The saved-run names each side of a step is read from (reused runs included)."""
    if step.get("planned"):
        return {"before": [], "after": []}
    names = {}
    for side in ("before", "after"):
        spec = step[side]
        if "reuse" in spec:
            names[side] = [spec["reuse"]]
        else:
            names[side] = [run_name(step["id"], side, n) for n in range(1, spec.get("repeats", 1) + 1)]
    return names


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_json(path, value):
    with Path(path).open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run_status(name, out_root=None) -> dict:
    """{"name", "state": "none" | "partial" | "complete", "cases_saved", "cases_total"}."""
    folder = Path(out_root or config.EXPERIMENTS_OUT) / name
    manifest_path = folder / MANIFEST
    if not manifest_path.is_file():
        return {"name": name, "state": "none", "cases_saved": 0, "cases_total": None}
    manifest = _read_json(manifest_path)
    saved = len(_completed(folder, manifest["modes"]))
    state = "complete" if manifest.get("status") == "complete" and (folder / EVALUATION).is_file() else "partial"
    return {"name": name, "state": state, "cases_saved": saved,
            "cases_total": len(manifest["case_set"]["cases"]),
            "cases_in_set": manifest["case_set"]["cases_in_set"]}


def list_steps(out_root=None, registry=None) -> list[dict]:
    """Every step with its question and the state of each saved run it reads."""
    rows = []
    for step in registry if registry is not None else load_registry():
        runs = runs_for(step)
        statuses = []
        for side in ("before", "after"):
            for name in runs[side]:
                status = run_status(name, out_root)
                status["reused"] = "reuse" in step[side]
                statuses.append(status)
        own = [s for s in statuses if not s["reused"]]     # a reused run is another step's
        if step.get("planned"):
            state = "planned (later task)"
        elif own and all(s["state"] == "complete" for s in own):
            state = "run"
        elif any(s["state"] != "none" for s in own):
            state = "partly run"
        else:
            state = "not run yet"
        rows.append({"step": step, "state": state, "runs": statuses})
    return rows


# --- results log (written after every case) --------------------------------------------

def _log_lines(folder) -> list[dict]:
    path = Path(folder) / RESULTS_LOG
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            break          # a line cut off by a crash; it and anything after are redone
    return records


def _completed(folder, modes) -> dict[str, dict]:
    return {r["case_id"]: r for r in _log_lines(folder) if all(m in r for m in modes)}


def _trim_log(folder) -> None:
    """Drop a final line cut off mid-write, so appended lines stay whole."""
    path = Path(folder) / RESULTS_LOG
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    good = []
    for line in text.splitlines():
        try:
            json.loads(line)
        except json.JSONDecodeError:
            break
        good.append(line)
    clean = "".join(line + "\n" for line in good)
    if clean != text:
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(clean)


def _append(folder, record) -> None:
    with (Path(folder) / RESULTS_LOG).open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


# --- provenance -------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def git_state(root=None) -> dict:
    """Commit and whether tracked files differ from it (line endings ignored)."""
    root = str(root or config._REPO_ROOT)
    try:
        head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True,
                              text=True, timeout=30)
        diff = subprocess.run(["git", "-C", root, "diff", "HEAD", "--ignore-cr-at-eol", "--name-only"],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "dirty": None, "dirty_paths": []}
    if head.returncode != 0:
        return {"commit": None, "dirty": None, "dirty_paths": []}
    paths = sorted(line for line in diff.stdout.splitlines() if line.strip())
    return {"commit": head.stdout.strip(), "dirty": bool(paths), "dirty_paths": paths[:50]}


def _requested_model() -> str:
    from triagebot.llm.openrouter import configured_model

    return configured_model()


# --- planning -------------------------------------------------------------------------------

def plan(step_id, side=None, repeat=1, limit=None, out_root=None, samples_dir=None,
         registry=None) -> list[dict]:
    """What a paid run would do, per side, without calling a model.

    Each plan holds the case set and its fingerprint, the profile and its
    settings, the modes, the cases still to run (finished cases in an
    existing results.jsonl are skipped), the number of calls and the estimated
    cost from config.EXPERIMENT_COST_PER_CASE.
    """
    step = get_step(step_id, registry)
    if step.get("planned"):
        raise ExperimentError(f"step {step['id']} is not runnable yet: {step['planned']}")
    if side not in (None, "before", "after"):
        raise ExperimentError(f"side must be before or after, not {side!r}")
    if limit is not None and limit < 1:
        raise ExperimentError("--limit must be at least 1")
    sides = [side] if side else [s for s in ("before", "after") if "reuse" not in step[s]]
    out_root = Path(out_root or config.EXPERIMENTS_OUT)
    alerts, set_manifest = eval_sets.load_set(step["case_set"], samples_dir)
    selected = alerts[:limit] if limit else alerts
    plans = []
    for name_side in sides:
        spec = step[name_side]
        if "reuse" in spec:
            raise ExperimentError(
                f"step {step['id']} {name_side} reuses the saved run {spec['reuse']}; there is "
                f"nothing to run (run it under its own step)")
        planned_repeats = spec.get("repeats", 1)
        if not 1 <= repeat <= planned_repeats:
            raise ExperimentError(f"step {step['id']} {name_side} is planned with {planned_repeats} "
                                  f"run(s); --repeat must be 1" + (f" to {planned_repeats}" if planned_repeats > 1 else ""))
        name = run_name(step["id"], name_side, repeat)
        folder = out_root / name
        settings = profiles.get(spec["profile"])
        modes = list(spec["modes"])
        model = _requested_model()
        existing = folder / MANIFEST
        if existing.is_file():
            old = _read_json(existing)
            changed = [label for label, a, b in (
                ("profile", old["profile"]["settings"], settings),
                ("profile name", old["profile"]["name"], spec["profile"]),
                ("case set", old["case_set"]["sha256"], set_manifest["sample"]["sha256"]),
                ("modes", old["modes"], modes),
                ("model", old["model"]["requested"], model)) if a != b]
            if changed:
                raise ExperimentError(
                    f"{name} was started with a different {', '.join(changed)}; delete "
                    f"{eval_sets.repo_path(folder)}/ to start it again")
            if len(old["case_set"]["cases"]) > len(selected):
                raise ExperimentError(
                    f"{name} already covers {len(old['case_set']['cases'])} cases; a smaller "
                    f"--limit would replace its results (raise or omit --limit)")
        done = _completed(folder, modes)
        remaining = [a for a in selected if a["case_id"] not in done]
        worksheet = settings["REVIEW_WORKSHEET_ENABLED"]
        per_case = sum(config.EXPERIMENT_CALLS_PER_CASE[m] for m in modes)
        plans.append({
            "step": step, "side": name_side, "repeat": repeat, "name": name, "dir": folder,
            "profile": spec["profile"], "settings": settings, "modes": modes, "model": model,
            "case_set": step["case_set"], "case_set_sha256": set_manifest["sample"]["sha256"],
            "cases_in_set": len(alerts), "limit": limit, "alerts": selected,
            "remaining": remaining, "already_saved": len(selected) - len(remaining),
            "calls": len(remaining) * per_case,
            "max_repair_calls": len(remaining) * len(modes) if worksheet else 0,
            "estimated_cost": round(len(remaining) * sum(
                config.EXPERIMENT_COST_PER_CASE[m] for m in modes), 4),
        })
    return plans


# --- running (paid) -------------------------------------------------------------------------

def _start_manifest(plan_, git) -> dict:
    folder = plan_["dir"]
    session = {"started_at": _now(), "finished_at": None, "git_commit": git["commit"],
               "git_dirty": git["dirty"], "cases_before": plan_["already_saved"]}
    path = folder / MANIFEST
    if path.is_file():
        manifest = _read_json(path)
        manifest["sessions"].append(session)
        manifest["status"] = "running"
        manifest["finished_at"] = None
    else:
        step = plan_["step"]
        manifest = {
            "run": plan_["name"], "step": step["id"], "side": plan_["side"],
            "repeat": plan_["repeat"], "title": step["title"], "question": step["question"],
            "profile": {"name": plan_["profile"], "settings": plan_["settings"],
                        "engineering_fixes": list(profiles.ENGINEERING_FIXES)},
            "modes": plan_["modes"],
            "configurations": [c for m in plan_["modes"] for c in CONFIGURATIONS[m]],
            "model": {"requested": plan_["model"], "reported": []},
            "temperature": config.REVIEW_TEMPERATURE,
            "max_tokens": config.REVIEW_MAX_TOKENS,
            "benchmark_commit": config.BENCHMARK_COMMIT,
            "started_at": session["started_at"], "finished_at": None,
            "status": "running", "sessions": [session],
        }
    manifest["case_set"] = {
        "name": plan_["case_set"], "sha256": plan_["case_set_sha256"],
        "file": f"{eval_sets.repo_path(config.SAMPLES_DIR)}/{plan_['case_set']}.json",
        "cases_in_set": plan_["cases_in_set"], "limit": plan_["limit"],
        "cases": [a["case_id"] for a in plan_["alerts"]],
    }
    manifest["git"] = git
    _write_json(path, manifest)
    return manifest


def _case_record(alert, modes, triage, caller_factory, kb, benchmark_root) -> dict:
    record = {"case_id": alert["case_id"]}
    for mode in modes:
        run = triage(alert, mode, caller_factory, kb, benchmark_root)
        entry = {"review": run["review"], "role_reports": run["role_reports"]}
        if mode == "council":
            entry["validated"] = run["validated"]
        record[mode] = entry
    return record


def execute(plan_, answer_key, caller_factory=None, benchmark_root=None, progress=None) -> dict:
    """Run the plan's remaining cases (paid), saving after every case, then finalise.

    Call only after the user confirmed the plan's estimate. Returns the final
    manifest. ``progress(done, total, case_id)`` is called after each case.
    """
    from triagebot import pipeline
    from triagebot.llm.openrouter import OpenRouterCaller
    from triagebot.nodes.context.retrieval import KnowledgeBase

    folder = Path(plan_["dir"])
    folder.mkdir(parents=True, exist_ok=True)
    _trim_log(folder)
    _start_manifest(plan_, git_state())
    factory = caller_factory or (lambda: OpenRouterCaller(model=plan_["model"]))
    with profiles.use_profile(plan_["profile"]):
        kb = KnowledgeBase()           # created inside the profile: it reads RETRIEVAL_MODE
        total = len(plan_["remaining"])
        for number, alert in enumerate(plan_["remaining"], 1):
            record = _case_record(alert, plan_["modes"], pipeline.triage, factory, kb, benchmark_root)
            _append(folder, record)
            if progress:
                progress(number, total, alert["case_id"])
    return finalize(folder, answer_key)


# --- finalising and scoring (evaluation side) -------------------------------------------------

def configurations_from_log(folder, manifest) -> dict[str, dict]:
    """Evaluator-format {name: {"model", "results"}} from results.jsonl, in case-set order."""
    done = _completed(folder, manifest["modes"])
    missing = [c for c in manifest["case_set"]["cases"] if c not in done]
    if missing:
        raise ExperimentError(f"{manifest['run']}: {len(missing)} case(s) not saved yet")
    results = {name: [] for mode in manifest["modes"] for name in CONFIGURATIONS[mode]}
    for case_id in manifest["case_set"]["cases"]:
        record = done[case_id]
        if "single" in record:
            results["B-single-agent"].append(record["single"]["review"])
        if "council" in record:
            results["C-council"].append(record["council"]["review"])
            results["D-validated-council"].append(record["council"]["validated"])
    out = {}
    for name, rows in results.items():
        model = next((r.get("model") for r in rows if r.get("model")), None)
        out[name] = {"model": model, "results": rows}
    return out


def _totals(folder, manifest) -> dict:
    done = _completed(folder, manifest["modes"])
    calls = failed = prompt = completion = 0
    cost = 0.0
    models = set()
    for case_id in manifest["case_set"]["cases"]:
        for mode in manifest["modes"]:
            entry = done[case_id][mode]
            for report in entry["role_reports"]:
                calls += 1
                failed += str(report.get("explanation", "")).startswith(FAILED_CALL_PREFIX)
                if report.get("model"):
                    models.add(report["model"])
            usage = entry["review"].get("usage") or {}       # summed over the case's calls
            prompt += usage.get("prompt_tokens") or 0
            completion += usage.get("completion_tokens") or 0
            cost += usage.get("cost") or 0.0
    return {"model_calls": calls, "failed_calls": failed, "prompt_tokens": prompt,
            "completion_tokens": completion, "cost_usd": round(cost, 6),
            "models": sorted(models)}


def score(case_ids, answer_key_path, configurations) -> tuple[dict, dict]:
    """(evaluation, evaluation_by_cwe) for saved configurations; reads the answer key."""
    from triagebot.nodes.ingest.answer_key import load_answer_key
    from triagebot.nodes.score import evaluate as scoring, final_report

    key = load_answer_key(answer_key_path)
    labels = {case_id: entry["vulnerable"] for case_id, entry in key.items()}
    configs = {name: (data["results"], data.get("model")) for name, data in configurations.items()}
    return (scoring.evaluate(case_ids, labels, configs),
            final_report.build(sorted(set(case_ids)), key, configs))


def finalize(folder, answer_key) -> dict:
    """Write B/C/D, the evaluation, the totals and report.md once every case is saved."""
    folder = Path(folder)
    manifest = _read_json(folder / MANIFEST)
    configurations = configurations_from_log(folder, manifest)
    for name, data in configurations.items():
        _write_json(folder / f"{name}.json", data)
    evaluation, by_cwe = score(manifest["case_set"]["cases"], answer_key, configurations)
    _write_json(folder / EVALUATION, evaluation)
    _write_json(folder / EVALUATION_BY_CWE, by_cwe)
    totals = _totals(folder, manifest)
    manifest["model"]["reported"] = totals.pop("models")
    manifest["totals"] = totals
    manifest["finished_at"] = _now()
    manifest["sessions"][-1]["finished_at"] = manifest["finished_at"]
    manifest["status"] = "complete"
    _write_json(folder / MANIFEST, manifest)
    with (folder / REPORT).open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(report_markdown(folder))
    return manifest


# --- showing (free, offline) ------------------------------------------------------------------

def _value(config_row, key):
    value = config_row
    for part in key.split("."):
        value = None if value is None else value.get(part)
    return value


def _format(value, kind, row):
    if value is None:
        return "–"
    if kind == "pct":
        return f"{value:.1%}"
    if kind == "of_genuine":
        return f"{value} of {row['genuine_in_sample']}"
    if kind == "of_fp":
        return f"{value} of {row['fp_in_sample']}"
    if kind == "of_all":
        return f"{value} of {row['evaluated_findings']}"
    if kind == "money":
        return f"{value:.4f}"
    if kind == "float":
        return f"{value:.2f}"
    return f"{value:,}" if isinstance(value, int) else str(value)


def _difference(a, b, kind):
    if a is None or b is None:
        return "–"
    delta = b - a
    if kind == "pct":
        return f"{delta * 100:+.1f}"            # percentage points (see the legend)
    if kind == "money":
        return f"{delta:+.4f}"
    if kind == "float":
        return f"{delta:+.2f}"
    return f"{delta:+,}" if isinstance(delta, int) else f"{delta:+}"


def _short_config(name):
    return {"B-single-agent": "B single agent", "C-council": "C council (raw)",
            "D-validated-council": "D council (validated)"}.get(name, name)


def _letter(name):
    return name.split("-", 1)[0]


CONFIG_LEGEND = "B = single agent; C = council, raw; D = council after deterministic validation."


def show_table(step_id, out_root=None, registry=None) -> dict:
    """The before/after table for one step from saved evaluation files (no key needed).

    Returns {"step", "headers", "rows", "legend", "notes", "missing"}. A column
    is one configuration of one saved run, headed by its side and letter (for
    example "After C"); the legend names the run behind each side. Where a side
    has two identical runs, one more column per configuration ("Noise C") shows
    run 2 minus run 1: the noise between identical runs.
    """
    step = get_step(step_id, registry)
    out_root = Path(out_root or config.EXPERIMENTS_OUT)
    runs = runs_for(step)
    columns, notes, missing, loaded, legend = [], [], [], {}, []
    for side in ("before", "after"):
        for number, name in enumerate(runs[side], 1):
            side_label = side.capitalize() + (f" #{number}" if number > 1 else "")
            status = run_status(name, out_root)
            if status["state"] == "none":
                missing.append(name)
                continue
            if status["state"] == "partial":
                notes.append(f"{name} is not finished: {status['cases_saved']} of "
                             f"{status['cases_total']} cases saved.")
                continue
            folder = out_root / name
            evaluation = _read_json(folder / EVALUATION)
            manifest = _read_json(folder / MANIFEST)
            loaded[name] = {row["configuration"]: row for row in evaluation["configurations"]}
            limit = manifest["case_set"]["limit"]
            if limit:
                notes.append(f"{name} covers only the first {limit} of "
                             f"{manifest['case_set']['cases_in_set']} cases (--limit).")
            reused = f", reused from step {name.split('-')[0]}" if name.split("-")[0] != step["id"] else ""
            legend.append(f"{side_label}: run {name} ({manifest['profile']['name']} profile, "
                          f"{' and '.join(manifest['modes'])}{reused})")
            for config_name in manifest["configurations"]:
                columns.append((f"{side_label} {_letter(config_name)}", loaded[name][config_name]))
    noise = []
    for side in ("before", "after"):
        names = [n for n in runs[side] if n in loaded]
        if len(names) >= 2:
            first, second = names[0], names[1]
            legend.append(f"Noise: {second} minus {first}, two runs with identical settings "
                          "(the noise between identical runs); rates in percentage points.")
            for config_name in loaded[first]:
                if config_name != "A-scanner-only" and config_name in loaded[second]:
                    noise.append((f"Noise {_letter(config_name)}",
                                  loaded[first][config_name], loaded[second][config_name]))
    if columns:
        legend.append(CONFIG_LEGEND)
    headers = ["Measure"] + [label for label, _ in columns] + [label for label, _, _ in noise]
    rows = []
    for label, key, kind in METRICS:
        cells = [_format(_value(row, key), kind, row) for _, row in columns]
        cells += [_difference(_value(a, key), _value(b, key), kind) for _, a, b in noise]
        rows.append([label] + cells)
    return {"step": step, "headers": headers, "rows": rows if columns else [],
            "legend": legend, "notes": notes, "missing": missing}


def markdown_table(table) -> str:
    lines = ["| " + " | ".join(table["headers"]) + " |",
             "| --- |" + " ---: |" * (len(table["headers"]) - 1)]
    lines += ["| " + " | ".join(row) + " |" for row in table["rows"]]
    return "\n".join(lines)


def commands(step_id) -> dict[str, str]:
    base = "python -m triagebot experiment"
    return {"show": f"{base} show {step_id}", "replay": f"{base} replay {step_id}",
            "run": f"{base} run {step_id}"}


def report_markdown(folder) -> str:
    """report.md for one saved run, generated from its manifest and evaluation."""
    folder = Path(folder)
    manifest = _read_json(folder / MANIFEST)
    evaluation = _read_json(folder / EVALUATION)
    step_id, side = manifest["step"], manifest["side"]
    try:
        step = get_step(step_id)
        changes = step.get("changes", "")
    except (ExperimentError, OSError):
        changes = ""
    rows = {row["configuration"]: row for row in evaluation["configurations"]}
    configs = manifest["configurations"]
    table = {"headers": ["Measure"] + [_short_config(c) for c in configs],
             "rows": [[label] + [_format(_value(rows[c], key), kind, rows[c]) for c in configs]
                      for label, key, kind in METRICS]}
    settings = manifest["profile"]["settings"]
    case_set = manifest["case_set"]
    totals = manifest.get("totals", {})
    git = manifest.get("git") or {}
    cases_run = len(case_set["cases"])
    scope = (f"{cases_run} of {case_set['cases_in_set']} cases (the first {case_set['limit']}, a smoke test)"
             if case_set["limit"] else f"all {cases_run} cases")
    lines = [
        f"# Step {step_id}, {side} side: {manifest['question']}",
        "",
        f"Run `{manifest['run']}`, finished {manifest['finished_at']} (UTC).",
        "",
        "## What changed",
        "",
        changes,
        "",
        f"This side ran the `{manifest['profile']['name']}` profile with "
        f"{' and '.join(manifest['modes'])} review:",
        "",
        "| Setting | Value |",
        "| --- | --- |",
    ]
    for key in profiles.SETTINGS:
        value = settings[key]
        shown = ("on" if value else "off") if isinstance(value, bool) else str(value)
        lines.append(f"| {profiles.LABELS[key]} | {shown} |")
    lines += [
        "",
        "On in every profile: " + "; ".join(manifest["profile"]["engineering_fixes"]) + ".",
        "",
        "## Results",
        "",
        f"Case set `{case_set['name']}` ({scope}), SHA-256 `{case_set['sha256'][:12]}`. "
        "Precision, recall and F1 count a case sent to a human as kept.",
        "",
        markdown_table(table),
        "",
        f"Model `{manifest['model']['requested']}`, temperature {manifest['temperature']}. "
        f"{totals.get('model_calls', 0)} model calls, {totals.get('failed_calls', 0)} failed; "
        f"total cost US${totals.get('cost_usd', 0):.4f}; "
        f"{totals.get('prompt_tokens', 0):,} prompt tokens.",
        f"Code: commit `{(git.get('commit') or 'unknown')[:12]}`"
        + (" with uncommitted changes." if git.get("dirty") else "."),
        "",
        "## Reproduce",
        "",
        f"- Show the before/after table (free, offline): `{commands(step_id)['show']}`",
        f"- Re-score the saved outputs (free, needs the Benchmark answer key): "
        f"`{commands(step_id)['replay']}`",
        f"- Re-run (paid, asks first): delete this folder, then "
        f"`{commands(step_id)['run']} --side {side}"
        + (f" --repeat {manifest['repeat']}" if manifest["repeat"] > 1 else "")
        + (f" --limit {case_set['limit']}" if case_set["limit"] else "") + "`",
        "",
    ]
    return "\n".join(lines)


# --- replay (free, needs the answer key) ------------------------------------------------------

def _normal(value):
    return json.loads(json.dumps(value, sort_keys=True))


def replay(step_id, answer_key, out_root=None, samples_dir=None, registry=None) -> list[dict]:
    """Re-score every finished run the step reads; report whether the numbers match.

    No model calls. Each result: {"run", "checks": {name: bool}, "matches": bool}.
    """
    step = get_step(step_id, registry)
    out_root = Path(out_root or config.EXPERIMENTS_OUT)
    results = []
    for side in ("before", "after"):
        for name in runs_for(step)[side]:
            if run_status(name, out_root)["state"] != "complete":
                continue
            folder = out_root / name
            manifest = _read_json(folder / MANIFEST)
            saved = {c: _read_json(folder / f"{c}.json") for c in manifest["configurations"]}
            rebuilt = configurations_from_log(folder, manifest)
            _, set_manifest = eval_sets.load_set(manifest["case_set"]["name"], samples_dir)
            evaluation, by_cwe = score(manifest["case_set"]["cases"], answer_key, saved)
            checks = {
                "case set fingerprint": set_manifest["sample"]["sha256"] == manifest["case_set"]["sha256"],
                "saved outputs match results.jsonl": _normal(saved) == _normal(rebuilt),
                "evaluation.json": _normal(evaluation) == _read_json(folder / EVALUATION),
                "evaluation_by_cwe.json": _normal(by_cwe) == _read_json(folder / EVALUATION_BY_CWE),
            }
            results.append({"run": name, "checks": checks, "matches": all(checks.values())})
    return results
