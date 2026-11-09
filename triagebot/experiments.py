"""Experiment runner: plan, run, show and replay the steps in EXPERIMENTS.md.

The steps live in experiments/registry.json, in story order. A step has two
numbers: its internal ID ("id": 1, 1b, 1c, 2 to 6), which names its run folders
and is what every function here takes, and its display number ("display": 1 to
7), which is what the user sees and types. resolve_step() turns what the user
typed into a step: a plain number is the display number, "1b" and "1c" are
internal IDs, and "id:N" reaches an internal numeric ID. A supplementary step
(1c) has no display number: list_steps() leaves it out, but it can still be
shown and replayed by its ID.

Each step has a "before" and an
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

show_table() shows one column per side and review mode: the single agent (B)
and the validated council (D, the version that ships). The raw council (C) stays
in the saved files and evaluation.json; it was identical to D in every run.

A step whose case set is the final test (step 7, internal 6) is run once. final_test_guard()
refuses to start it on a working tree with uncommitted changes to tracked files
(the run records the commit it ran on), and refuses a fresh run once a run has
results; resuming an interrupted run is allowed (it is the same run). Starting
over needs RERUN_FLAG, and the old results are moved aside, not deleted.

The mutation test (step 6, internal 5, "scoring": "mutation" in the registry) runs its after
side ("source": "mutant") from one overlay root per case (triagebot/mutants.py)
and scores it against the flipped answers ("labels": "flipped"). Once both sides
are finished, finalize() also writes <step>-after/mutation_score.json: killed,
survived and escalated pairs and the mutation score per configuration and
direction. Its sides must run on one commit ("same_commit": true):
same_commit_guard() refuses a dirty tree, or a commit other than the one a saved
run of the step recorded.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

from triagebot import config, profiles
from triagebot.nodes.ingest import eval_sets, mutation_set

MODES = ("single", "council")
FINAL_TEST = "final-test"
RERUN_FLAG = "--i-know-this-reruns-the-final-test"
SUPERSEDED = "superseded"          # <run>-superseded-<UTC time>/: results moved aside by a rerun
CONFIGURATIONS = {"single": ("B-single-agent",), "council": ("C-council", "D-validated-council")}
RESULTS_LOG = "results.jsonl"
MANIFEST = "run_manifest.json"
EVALUATION = "evaluation.json"
EVALUATION_BY_CWE = "evaluation_by_cwe.json"
REPORT = "report.md"
MUTATION_SCORE = "mutation_score.json"       # the mutation step (internal 5): in the after side's folder
SOURCES = ("benchmark", "mutant")            # where a side reads the case's code from
FLIPPED = "flipped"                          # a side scored against the flipped answers
FAILED_CALL_PREFIX = "Model call failed"     # report.failure() explanation

# (label, key, kind) for report.md (every configuration, B, C and D); kind formats the value.
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
# The terminal table (show_table): the configuration shown per review mode, and the rows.
# Invalid answers appear only when a column has any.
SHOWN = {"single": "B-single-agent", "council": "D-validated-council"}
DISPLAY_METRICS = (
    ("Real vulnerabilities dismissed", "genuine_dismissed", "of_genuine"),
    ("False alarms removed", "fp_removed", "of_fp"),
    ("Sent to a human", "human_review", "of_all"),
    ("Precision", "precision", "pct"),
    ("Recall", "recall", "pct"),
    ("F1", "f1", "pct"),
    ("Invalid answers", "invalid_outputs", "int"),
    ("Cost (US$)", "usage.cost_total", "usd"),
    ("Mean time per case (s)", "usage.latency_mean_seconds", "seconds"),
)
OF = {"of_genuine": "genuine_in_sample", "of_fp": "fp_in_sample", "of_all": "evaluated_findings"}
F1_NOTE = "F1 counts a case sent to a human as kept."
# The per-CWE table (show_table(..., by_cwe=True); `experiment show STEP --by-cwe`).
CWE_METRICS = (
    ("F1", "f1", "pct"),
    ("Real vulnerabilities dismissed", "genuine_dismissed", "of_genuine"),
    ("False alarms removed", "fp_removed", "of_fp"),
    ("Sent to a human", "human_review", "of_all"),
)
CWE_NAMES = {"CWE-22": "Path traversal", "CWE-78": "Command injection",
             "CWE-79": "Cross-site scripting", "CWE-89": "SQL injection"}
CASE_SET_NAMES = {"pilot": "Pilot", "comparison": "Comparison", "final-test": "Final test",
                  "mutation": "Mutation"}


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
                if spec.get("source", "benchmark") not in SOURCES:
                    raise ExperimentError(f"step {step['id']} {side}: bad source {spec['source']!r}")
                if (spec.get("source") == "mutant") != (spec.get("labels") == FLIPPED):
                    raise ExperimentError(f"step {step['id']} {side}: a mutant side is scored "
                                          f"against the flipped answers, and only a mutant side")
    numbers = [step["display"] for step in steps if step.get("display") is not None]
    if len(numbers) != len(set(numbers)):
        raise ExperimentError(f"two steps share a display number: {numbers}")
    return steps


def is_mutation_step(step) -> bool:
    return step.get("scoring") == "mutation"


def get_step(step_id, registry=None) -> dict:
    """The step with this internal ID (as in its run folder names)."""
    steps = registry if registry is not None else load_registry()
    for step in steps:
        if step["id"] == str(step_id):
            return step
    raise ExperimentError(f"unknown step {step_id!r}; choose from {', '.join(s['id'] for s in steps)}")


def _choices(steps) -> str:
    numbers = sorted(s["display"] for s in steps if s.get("display") is not None)
    return f"{numbers[0]} to {numbers[-1]} (see experiment list)" if numbers else "a step in the registry"


def resolve_step(text, registry=None) -> dict:
    """The step the user typed: a plain number is the display number (`5` is internal 4);
    other IDs (`1b`, `1c`) are internal; `id:N` reaches the internal ID N."""
    steps = registry if registry is not None else load_registry()
    text = str(text).strip()
    if text.lower().startswith("id:"):
        try:
            return get_step(text[3:].strip(), steps)
        except ExperimentError:
            raise ExperimentError(f"unknown step {text!r}: no internal step ID "
                                  f"{text[3:].strip()!r}") from None
    if text.isdigit():
        for step in steps:
            if step.get("display") == int(text):
                return step
    else:
        for step in steps:
            if step["id"] == text:
                return step
    raise ExperimentError(f"unknown step {text!r}; choose {_choices(steps)}")


def step_label(step) -> str:
    """What the user sees: "Step 7", or "Supplementary step 1c"."""
    if step.get("display") is not None:
        return f"Step {step['display']}"
    return f"Supplementary step {step['id']}" if step.get("supplementary") else f"Step {step['id']}"


def _name(step) -> str:
    """step_label() in the middle of a sentence."""
    label = step_label(step)
    return label[0].lower() + label[1:]


def column_label(step, side, mode) -> str:
    """The table column of one side and review mode ("side_labels" in the registry: one name
    per side, or one per mode of a side)."""
    label = step.get("side_labels", {}).get(side)
    if isinstance(label, dict):
        label = label.get(mode)
    return label or f"{side.capitalize()} · {'single agent' if mode == 'single' else 'council'}"


def case_set_label(name, samples_dir=None) -> str:
    """"Comparison · 96", "Mutation · 22 pairs", "Final test · 120" (from the set's manifest)."""
    title = CASE_SET_NAMES.get(name, name)
    path = Path(samples_dir or config.SAMPLES_DIR) / f"{name}.manifest.json"
    try:
        cases = _read_json(path)["cases"]
    except (OSError, ValueError, KeyError):
        return title
    return f"{title} · {cases}" + (" pairs" if name == "mutation" else "")


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
        return {"name": name, "state": "none", "cases_saved": 0, "cases_total": None,
                "finished_at": None}
    manifest = _read_json(manifest_path)
    saved = len(_completed(folder, manifest["modes"]))
    state = "complete" if manifest.get("status") == "complete" and (folder / EVALUATION).is_file() else "partial"
    return {"name": name, "state": state, "cases_saved": saved,
            "cases_total": len(manifest["case_set"]["cases"]),
            "cases_in_set": manifest["case_set"]["cases_in_set"],
            "finished_at": manifest.get("finished_at")}


def list_steps(out_root=None, registry=None, include_supplementary=False) -> list[dict]:
    """Every step in story order (display number) with the state of each saved run it reads.

    Supplementary steps (no display number, such as 1c) are left out unless asked for.
    """
    steps = registry if registry is not None else load_registry()
    steps = [s for s in steps if include_supplementary or not s.get("supplementary")]
    steps = sorted(steps, key=lambda s: (s.get("display") is None, s.get("display") or 0))
    rows = []
    for step in steps:
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

def cost_per_case(step) -> dict[str, float]:
    """US$ per case by mode: the step's own estimate (registry "cost_per_case") if it has
    one, else config.EXPERIMENT_COST_PER_CASE."""
    return {**config.EXPERIMENT_COST_PER_CASE, **step.get("cost_per_case", {})}


def plan(step_id, side=None, repeat=1, limit=None, out_root=None, samples_dir=None,
         registry=None, fresh=False) -> list[dict]:
    """What a paid run would do, per side, without calling a model.

    Each plan holds the case set and its fingerprint, the profile and its
    settings, the modes, the cases still to run (finished cases in an
    existing results.jsonl are skipped), the number of calls and the estimated
    cost from cost_per_case(). ``fresh`` plans a start from nothing, ignoring
    any existing run folder (a final-test rerun moves it aside before running).
    """
    step = get_step(step_id, registry)
    if step.get("planned"):
        raise ExperimentError(f"{_name(step)} is not runnable yet: {step['planned']}")
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
                f"{_name(step)} {name_side} reuses the saved run {spec['reuse']}; there is "
                f"nothing to run (run it under its own step)")
        planned_repeats = spec.get("repeats", 1)
        if not 1 <= repeat <= planned_repeats:
            raise ExperimentError(f"{_name(step)} {name_side} is planned with {planned_repeats} "
                                  f"run(s); --repeat must be 1" + (f" to {planned_repeats}" if planned_repeats > 1 else ""))
        name = run_name(step["id"], name_side, repeat)
        folder = out_root / name
        settings = profiles.get(spec["profile"])
        retrieval = profiles.retrieval_provenance(settings)
        modes = list(spec["modes"])
        model = _requested_model()
        source = spec.get("source", "benchmark")
        labels = spec.get("labels", "answer key")
        if source == "mutant":
            mutations = mutation_set.load_mutations(samples_dir)
            if sorted(mutations) != sorted(a["case_id"] for a in alerts):
                raise ExperimentError(f"{_name(step)}: the mutations do not match the case set")
        existing = folder / MANIFEST
        if existing.is_file() and not fresh:
            old = _read_json(existing)
            changed = [label for label, a, b in (
                ("profile", old["profile"]["settings"], settings),
                ("profile name", old["profile"]["name"], spec["profile"]),
                ("retrieval set-up", old.get("retrieval"), retrieval),
                ("case set", old["case_set"]["sha256"], set_manifest["sample"]["sha256"]),
                ("modes", old["modes"], modes),
                ("source", old.get("source", {}).get("kind", "benchmark"), source),
                ("model", old["model"]["requested"], model)) if a != b]
            if changed:
                raise ExperimentError(
                    f"{name} was started with a different {', '.join(changed)}; delete "
                    f"{eval_sets.repo_path(folder)}/ to start it again")
            if len(old["case_set"]["cases"]) > len(selected):
                raise ExperimentError(
                    f"{name} already covers {len(old['case_set']['cases'])} cases; a smaller "
                    f"--limit would replace its results (raise or omit --limit)")
        done = {} if fresh else _completed(folder, modes)
        remaining = [a for a in selected if a["case_id"] not in done]
        worksheet = settings["REVIEW_WORKSHEET_ENABLED"]
        per_case = sum(config.EXPERIMENT_CALLS_PER_CASE[m] for m in modes)
        costs = {m: cost_per_case(step)[m] for m in modes}
        plans.append({
            "step": step, "side": name_side, "repeat": repeat, "name": name, "dir": folder,
            "profile": spec["profile"], "settings": settings, "retrieval": retrieval,
            "modes": modes, "model": model, "source": source, "labels": labels,
            "case_set": step["case_set"], "case_set_sha256": set_manifest["sample"]["sha256"],
            "cases_in_set": len(alerts), "limit": limit, "alerts": selected,
            "remaining": remaining, "already_saved": len(selected) - len(remaining),
            "calls": len(remaining) * per_case,
            "max_repair_calls": len(remaining) * len(modes) if worksheet else 0,
            "cost_per_case": costs,
            "estimated_cost": round(len(remaining) * sum(costs.values()), 4),
        })
    return plans


# --- the final test is run once (step 7, internal 6) ----------------------------------------

def is_final_test(step) -> bool:
    return step.get("case_set") == FINAL_TEST


def final_test_guard(plans, rerun=False, git=None) -> list[dict]:
    """Refuse to start a final-test run that must not start; return the runs a rerun replaces.

    Applies to every step whose case set is the final test (other steps pass
    through, but ``rerun`` is refused for them):

    1. The working tree must have no uncommitted changes to tracked files
       (git_state()), because the run records the commit it ran on.
    2. A run that already has results (complete over the whole case set) is not
       started again unless ``rerun`` (RERUN_FLAG). An unfinished run resumes
       without the flag: it is the same run.

    Returns [{"name", "dir", "state", "cases_saved"}] for the existing runs that
    start_over() would move aside (only with ``rerun``). Raises ExperimentError.
    """
    if not plans:
        return []
    step = plans[0]["step"]
    if not is_final_test(step):
        if rerun:
            raise ExperimentError(f"{RERUN_FLAG} applies only to a step whose case set is "
                                  f"{FINAL_TEST}; {_name(step)} uses {step['case_set']}")
        return []
    git = git if git is not None else git_state()
    if git.get("commit") is None:
        raise ExperimentError(
            f"{_name(step)} runs the final test, which records the commit it ran on, but the "
            "Git commit could not be read; run it from a Git checkout of this repository")
    if git.get("dirty"):
        paths = git.get("dirty_paths") or []
        shown = ", ".join(paths[:10]) + (f" and {len(paths) - 10} more" if len(paths) > 10 else "")
        raise ExperimentError(
            f"{_name(step)} runs the final test, which records the commit it ran on: commit "
            f"first. Uncommitted changes to tracked files: {shown}")
    existing = []
    for plan_ in plans:
        status = run_status(plan_["name"], Path(plan_["dir"]).parent)
        if status["state"] == "none":
            continue
        full = status["state"] == "complete" and status["cases_total"] == status["cases_in_set"]
        if full and not rerun:
            raise ExperimentError(
                f"{plan_['name']} already has results on the final test, which is run once. "
                f"To start it again from nothing, pass {RERUN_FLAG} (the old results are moved "
                f"to {plan_['name']}-{SUPERSEDED}-<time>/, not deleted)")
        if rerun:
            existing.append({"name": plan_["name"], "dir": Path(plan_["dir"]),
                             "state": status["state"], "cases_saved": status["cases_saved"]})
    return existing


def same_commit_guard(plans, git=None) -> None:
    """For a step with "same_commit": true (step 6, internal 5): refuse unless both sides run on one
    commit.

    The working tree must have no uncommitted changes to tracked files, and every
    saved run of the step (either side, any session) must have recorded the current
    commit. Raises ExperimentError; other steps pass through.
    """
    if not plans or not plans[0]["step"].get("same_commit"):
        return
    step = plans[0]["step"]
    git = git if git is not None else git_state()
    if git.get("commit") is None:
        raise ExperimentError(f"{_name(step)} runs both sides on one commit, but the Git "
                              "commit could not be read; run it from a Git checkout of this repository")
    if git.get("dirty"):
        paths = git.get("dirty_paths") or []
        shown = ", ".join(paths[:10]) + (f" and {len(paths) - 10} more" if len(paths) > 10 else "")
        raise ExperimentError(f"{_name(step)} runs both sides on one commit: commit first. "
                              f"Uncommitted changes to tracked files: {shown}")
    out_root = Path(plans[0]["dir"]).parent
    for side, names in runs_for(step).items():
        if "reuse" in step[side]:
            continue
        for name in names:
            path = out_root / name / MANIFEST
            if not path.is_file():
                continue
            manifest = _read_json(path)
            commits = {s.get("git_commit") for s in manifest.get("sessions", [])}
            commits.add((manifest.get("git") or {}).get("commit"))
            other = sorted(c for c in commits if c != git["commit"])
            if other:
                raise ExperimentError(
                    f"{_name(step)} runs both sides on one commit, but {name} was run on "
                    f"{', '.join((c or 'an unknown commit')[:12] for c in other)}, not "
                    f"{git['commit'][:12]}; check out that commit, or delete "
                    f"{eval_sets.repo_path(out_root / name)}/ to run it again here")


def start_over(existing, now=None) -> list[Path]:
    """Move each existing run folder to <run>-superseded-<UTC time>/ (kept, not deleted)."""
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    moved = []
    for run in existing:
        folder = Path(run["dir"])
        target = folder.with_name(f"{folder.name}-{SUPERSEDED}-{stamp}")
        if target.exists():
            raise ExperimentError(f"{target} already exists; nothing was moved")
        folder.rename(target)
        moved.append(target)
    return moved


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
            **({"retrieval": plan_["retrieval"]} if plan_.get("retrieval") else {}),
            **(_source_provenance(plan_) if is_mutation_step(step) else {}),
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


def _source_provenance(plan_) -> dict:
    """Where a mutation-step side read its code from, and how it is scored."""
    from triagebot import mutants

    if plan_["source"] == "mutant":
        source = {"kind": "mutant", "overlay_dir": eval_sets.repo_path(mutants.overlay_dir()),
                  "trees": list(mutants.OVERLAY_TREES),
                  "note": "one overlay root per case: the Benchmark source with only the mutated file replaced"}
    else:
        source = {"kind": "benchmark", "note": "the Benchmark checkout, unchanged"}
    return {"source": source, "labels": plan_["labels"]}


def _case_record(alert, modes, triage, caller_factory, kb, benchmark_root, record_source=False) -> dict:
    record = {"case_id": alert["case_id"]}
    if record_source:                   # the exact file this case was judged on (LF SHA-256)
        record["source_sha256"] = eval_sets.file_sha256(Path(benchmark_root) / alert["file"])
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
    mutation = is_mutation_step(plan_["step"])
    roots = {}
    if mutation:
        root = benchmark_root or config.BENCHMARK_ROOT
        if not root or not Path(root).is_dir():
            raise ExperimentError("OWASP Benchmark source not found; set BENCHMARK_ROOT")
        roots = {a["case_id"]: root for a in plan_["remaining"]}
        if plan_["source"] == "mutant":           # built before any model call
            from triagebot import mutants

            mutations = mutation_set.load_mutations()
            roots = mutants.ensure_overlays(
                {c: mutations[c] for c in roots}, root)
    folder.mkdir(parents=True, exist_ok=True)
    _trim_log(folder)
    _start_manifest(plan_, git_state())
    factory = caller_factory or (lambda: OpenRouterCaller(model=plan_["model"]))
    with profiles.use_profile(plan_["profile"]):
        kb = KnowledgeBase()           # created inside the profile: it reads RETRIEVAL_MODE
        total = len(plan_["remaining"])
        for number, alert in enumerate(plan_["remaining"], 1):
            case_root = str(roots[alert["case_id"]]) if mutation else benchmark_root
            record = _case_record(alert, plan_["modes"], pipeline.triage, factory, kb, case_root,
                                  record_source=mutation)
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


def _answer_key(answer_key_path, flip_cases=()) -> dict:
    """The answer key, with the label of each case in ``flip_cases`` flipped (the mutants of internal step 5)."""
    from triagebot.nodes.ingest.answer_key import load_answer_key

    key = load_answer_key(answer_key_path)
    for case_id in flip_cases:
        key[case_id] = {**key[case_id], "vulnerable": not key[case_id]["vulnerable"]}
    return key


def score(case_ids, answer_key_path, configurations, flip=False) -> tuple[dict, dict]:
    """(evaluation, evaluation_by_cwe) for saved configurations; reads the answer key.

    ``flip``: score against the flipped answers (the mutants of internal step 5).
    """
    from triagebot.nodes.score import evaluate as scoring, final_report

    key = _answer_key(answer_key_path, case_ids if flip else ())
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
    evaluation, by_cwe = score(manifest["case_set"]["cases"], answer_key, configurations,
                               flip=manifest.get("labels") == FLIPPED)
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
    try:
        step = get_step(manifest["step"])
    except (ExperimentError, OSError):
        step = {}
    if is_mutation_step(step):
        write_mutation_score(step, answer_key, folder.parent)
    return manifest


# --- the mutation score (step 6, internal 5; evaluation side) --------------------------------

def mutation_score(step, answer_key, out_root=None) -> dict | None:
    """killed / survived / escalated per configuration and direction, from both sides' saved
    outputs; None until both sides are finished over the same cases."""
    from triagebot import mutants

    out_root = Path(out_root or config.EXPERIMENTS_OUT)
    runs = runs_for(step)
    names = {side: runs[side][0] for side in ("before", "after")}
    if any(run_status(name, out_root)["state"] != "complete" for name in names.values()):
        return None
    manifests = {side: _read_json(out_root / name / MANIFEST) for side, name in names.items()}
    cases = manifests["before"]["case_set"]["cases"]
    if sorted(cases) != sorted(manifests["after"]["case_set"]["cases"]):
        return None                     # a --limit smoke test on one side only
    outputs = {side: {c: _read_json(out_root / names[side] / f"{c}.json")["results"]
                      for c in manifests[side]["configurations"]} for side in names}
    key = _answer_key(answer_key)
    labels = {case_id: key[case_id]["vulnerable"] for case_id in cases}
    result = mutants.score_pairs(cases, labels, outputs["before"], outputs["after"])
    commits = {side: (m.get("git") or {}).get("commit") for side, m in manifests.items()}
    return {"step": step["id"], "before": names["before"], "after": names["after"],
            "cases": len(cases), "case_set_sha256": manifests["before"]["case_set"]["sha256"],
            "commits": commits, "same_commit": len(set(commits.values())) == 1, **result}


def write_mutation_score(step, answer_key, out_root=None) -> dict | None:
    out_root = Path(out_root or config.EXPERIMENTS_OUT)
    result = mutation_score(step, answer_key, out_root)
    if result is not None:
        _write_json(out_root / result["after"] / MUTATION_SCORE, result)
    return result


MUTATION_ROWS = (("Pairs", "pairs"), ("Original judged right", "precondition_met"),
                 ("Left out (original judged wrong)", "excluded_original_wrong"),
                 ("Verdict flipped correctly", "killed"), ("Verdict unchanged", "survived"),
                 ("Sent to a human", "escalated"))
MUTATION_DIRECTIONS = (("real_to_safe", "real → safe"), ("safe_to_real", "safe → real"))


def mutation_table(step, out_root=None) -> dict | None:
    """{"headers", "rows", "highlight"} from the saved mutation_score.json (offline), or None.

    One column per reviewer: the single agent (B) and the validated council (D); the raw
    council (C) stays in the file. The last rows split the mutation score by direction.
    """
    out_root = Path(out_root or config.EXPERIMENTS_OUT)
    path = out_root / runs_for(step)["after"][0] / MUTATION_SCORE
    if not path.is_file():
        return None
    configs = _read_json(path)["configurations"]
    shown = [(label, configs[name]) for label, name in (("Single agent", SHOWN["single"]),
                                                       ("Council", SHOWN["council"])) if name in configs]

    def score(group):
        value = group["mutation_score"]
        return "–" if value is None else f"{value:.1%}"

    rows = [[label] + [str(c["overall"][key]) for _, c in shown] for label, key in MUTATION_ROWS]
    rows.append(["Mutation score"] + [score(c["overall"]) for _, c in shown])
    highlight = len(rows) - 1
    for group, label in MUTATION_DIRECTIONS:
        rows.append([f"  {label}"] + [
            f"{score(c[group])} ({c[group]['killed']} of {c[group]['precondition_met']})"
            for _, c in shown])
    return {"headers": ["Measure"] + [label for label, _ in shown], "rows": rows,
            "highlight": highlight}


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
    if kind in OF:
        return f"{value} of {row[OF[kind]]}"
    if kind == "money":
        return f"{value:.4f}"
    if kind == "usd":
        return f"{value:.2f}"
    if kind == "float":
        return f"{value:.2f}"
    if kind == "seconds":
        return f"{value:.1f}"
    return f"{value:,}" if isinstance(value, int) else str(value)


def _short_config(name):
    return {"B-single-agent": "B single agent", "C-council": "C council (raw)",
            "D-validated-council": "D council (validated)"}.get(name, name)


def _plural(count, word):
    return f"{count} {word}" + ("" if count == 1 else "s")


def _rerun_difference(out_root, first, second, modes) -> str:
    """How two identical runs differed: the number of cases whose shown verdict changed."""
    differed = cases = 0
    for mode in modes:
        verdicts = []
        for name in (first, second):
            rows = _read_json(Path(out_root) / name / f"{SHOWN[mode]}.json")["results"]
            verdicts.append({r.get("case_id", n): r.get("verdict") for n, r in enumerate(rows)})
        common = set(verdicts[0]) & set(verdicts[1])
        cases = max(cases, len(common))
        differed += sum(verdicts[0][c] != verdicts[1][c] for c in common)
    return f"Identical rerun: differed on {_plural(differed, 'case')} of {cases}."


def show_table(step_id, out_root=None, registry=None, by_cwe=False) -> dict:
    """The table for one step from saved evaluation files (offline; no key needed).

    ``step_id`` is the internal ID (resolve_step() turns what the user typed into one).
    Returns {"step", "headers", "rows", "highlight", "rerun", "footer", "notes", "missing",
    "by_cwe", "mutation"}. A column is one review mode of one side's saved run, named by
    column_label(): the single agent (B) or the validated council (D). A row's "(of N)"
    holds the count every column shares. "highlight" is the index of the row the step is
    about (registry "highlight", a metric key), or None. Where a side has two identical runs,
    the second is not a column: "rerun" says on how many cases it differed. ``by_cwe`` adds
    {"headers", "rows", "group"}: the same columns per weakness, from evaluation_by_cwe.json
    ("group" rows per weakness; the weakness is named on its first row only).
    """
    step = get_step(step_id, registry)
    out_root = Path(out_root or config.EXPERIMENTS_OUT)
    runs = runs_for(step)
    columns, notes, missing, shown_runs, cwe_columns = [], [], [], [], []
    rerun = None
    for side in ("before", "after"):
        finished = []
        for name in runs[side]:
            status = run_status(name, out_root)
            if status["state"] == "none":
                missing.append(name)
            elif status["state"] == "partial":
                notes.append(f"{name} is not finished: {status['cases_saved']} of "
                             f"{status['cases_total']} cases saved.")
            else:
                finished.append(name)
        if not finished:
            continue
        name = finished[0]
        shown_runs.extend(finished)
        folder = out_root / name
        evaluation = {row["configuration"]: row for row in _read_json(folder / EVALUATION)["configurations"]}
        manifest = _read_json(folder / MANIFEST)
        limit = manifest["case_set"]["limit"]
        if limit:
            notes.append(f"{name} covers only the first {limit} of "
                         f"{manifest['case_set']['cases_in_set']} cases (--limit).")
        per_cwe = _read_json(folder / EVALUATION_BY_CWE)["by_cwe"] if by_cwe else {}
        for mode in manifest["modes"]:
            label = column_label(step, side, mode)
            columns.append({"label": label, "mode": mode, "row": evaluation[SHOWN[mode]]})
            if by_cwe:
                cwe_columns.append({"label": label, "mode": mode, "per": {
                    cwe: next(r for r in entry["configurations"] if r["configuration"] == SHOWN[mode])
                    for cwe, entry in per_cwe.items()}})
        if len(finished) >= 2:
            rerun = _rerun_difference(out_root, finished[0], finished[1], manifest["modes"])
    if is_mutation_step(step):          # reviewer by reviewer: original next to mutated
        columns.sort(key=lambda c: MODES.index(c["mode"]))
        cwe_columns.sort(key=lambda c: MODES.index(c["mode"]))
    rows, highlight = [], None
    for label, key, kind in DISPLAY_METRICS:
        values = [_value(c["row"], key) for c in columns]
        if key == "invalid_outputs" and not any(values):
            continue
        totals = {c["row"].get(OF[kind]) for c in columns} if kind in OF else set()
        if len(totals) == 1:            # every column has the same N: it goes in the row name
            label = f"{label} (of {totals.pop()})"
            cells = [_format(v, "int", c["row"]) for v, c in zip(values, columns)]
        else:
            cells = [_format(v, kind, c["row"]) for v, c in zip(values, columns)]
        if key == step.get("highlight"):
            highlight = len(rows)
        rows.append([label] + cells)
    by_cwe_table = None
    if cwe_columns:
        cwes = sorted({cwe for c in cwe_columns for cwe in c["per"]},
                      key=lambda c: int(c.split("-")[1]) if c.split("-")[-1].isdigit() else 0)
        cwe_rows = []
        for cwe in cwes:
            name = f"{cwe} {CWE_NAMES[cwe]}" if cwe in CWE_NAMES else cwe
            for number, (label, key, kind) in enumerate(CWE_METRICS):
                cwe_rows.append([name if number == 0 else "", label] + [
                    _format(_value(c["per"][cwe], key), kind, c["per"][cwe]) if cwe in c["per"] else "–"
                    for c in cwe_columns])
        by_cwe_table = {"headers": ["Weakness", "Measure"] + [c["label"] for c in cwe_columns],
                        "rows": cwe_rows, "group": len(CWE_METRICS)}
    footer = [F1_NOTE, "Runs: " + ", ".join(shown_runs) + "."] if columns else []
    return {"step": step, "headers": ["Measure"] + [c["label"] for c in columns],
            "rows": rows if columns else [], "highlight": highlight if columns else None,
            "rerun": rerun, "footer": footer, "notes": notes, "missing": missing,
            "by_cwe": by_cwe_table,
            "mutation": mutation_table(step, out_root) if is_mutation_step(step) else None}


def markdown_table(table, text_columns=1) -> str:
    lines = ["| " + " | ".join(table["headers"]) + " |",
             "|" + " --- |" * text_columns + " ---: |" * (len(table["headers"]) - text_columns)]
    lines += ["| " + " | ".join(row) + " |" for row in table["rows"]]
    return "\n".join(lines)


def commands(step) -> dict[str, str]:
    """The show / replay / run commands for a step (a step dict, or an internal ID), by the
    number the user types: the display number, or the ID of a supplementary step."""
    if not isinstance(step, dict):
        try:
            step = get_step(step)
        except (ExperimentError, OSError):
            step = {"id": str(step)}
    number = step["display"] if step.get("display") is not None else step["id"]
    base = "python -m triagebot experiment"
    return {"show": f"{base} show {number}", "replay": f"{base} replay {number}",
            "run": f"{base} run {number}"}


def report_markdown(folder) -> str:
    """report.md for one saved run, generated from its manifest and evaluation."""
    folder = Path(folder)
    manifest = _read_json(folder / MANIFEST)
    evaluation = _read_json(folder / EVALUATION)
    step_id, side = manifest["step"], manifest["side"]
    try:
        step = get_step(step_id)
        changes = step.get("details") or step.get("changes", "")
    except (ExperimentError, OSError):
        step = {"id": step_id}
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
        f"# {step_label(step)}, {side} side: {manifest['question']}",
        "",
        f"Internal step ID `{step_id}` (EXPERIMENTS.md, Step numbers).",
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
        *(["", "Code: each mutant was read from its own overlay root (the Benchmark source with "
               "only the mutated file replaced) and scored against the flipped answers; the "
               "mutation score is in the after side's mutation_score.json."]
          if manifest.get("labels") == FLIPPED else []),
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
        f"- Show the before/after table (free, offline): `{commands(step)['show']}`",
        f"- Re-score the saved outputs (free, needs the Benchmark answer key): "
        f"`{commands(step)['replay']}`",
        _rerun_line(step, side, manifest, case_set),
        "",
    ]
    return "\n".join(lines)


def _rerun_line(step, side, manifest, case_set) -> str:
    command = (f"{commands(step)['run']} --side {side}"
               + (f" --repeat {manifest['repeat']}" if manifest["repeat"] > 1 else "")
               + (f" --limit {case_set['limit']}" if case_set["limit"] else ""))
    if case_set["name"] == FINAL_TEST:
        return (f"- Re-run (paid, asks first; the final test is run once, so only on purpose): "
                f"`{command} {RERUN_FLAG}`, which moves this folder to "
                f"`{manifest['run']}-{SUPERSEDED}-<time>/`")
    return f"- Re-run (paid, asks first): delete this folder, then `{command}`"


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
            evaluation, by_cwe = score(manifest["case_set"]["cases"], answer_key, saved,
                                       flip=manifest.get("labels") == FLIPPED)
            checks = {
                "case set fingerprint": set_manifest["sample"]["sha256"] == manifest["case_set"]["sha256"],
                "saved outputs match results.jsonl": _normal(saved) == _normal(rebuilt),
                "evaluation.json": _normal(evaluation) == _read_json(folder / EVALUATION),
                "evaluation_by_cwe.json": _normal(by_cwe) == _read_json(folder / EVALUATION_BY_CWE),
            }
            if is_mutation_step(step) and side == "after":
                expected = mutation_score(step, answer_key, out_root)
                path = folder / MUTATION_SCORE
                if expected is not None:
                    checks[MUTATION_SCORE] = path.is_file() and _normal(expected) == _read_json(path)
            results.append({"run": name, "checks": checks, "matches": all(checks.values())})
    return results
