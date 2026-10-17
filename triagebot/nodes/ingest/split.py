"""Dev/test split and checkpoint sample selection. EVALUATION SIDE ONLY.

The answer key is used here to STRATIFY the split and to SELECT and
BALANCE the sample, but the alerts returned by select_sample() carry
only NormalisedAlert fields, so they are safe to hand to the pipeline.
"""

from collections import defaultdict
import random

from triagebot.nodes.ingest.mapping import cwe_matches
from triagebot.schemas import AnswerKeyEntry, NormalisedAlert

_ALERT_FIELDS = tuple(NormalisedAlert.__annotations__)


def _strata(answer_key):
    strata = defaultdict(list)
    for case_id, entry in answer_key.items():
        strata[entry["category"], entry["vulnerable"]].append(case_id)
    return strata


def assign_split(answer_key: dict[str, AnswerKeyEntry], seed: int,
                 test_fraction: float) -> dict[str, str]:
    """{case_id: "dev" | "test"}, stratified by (category, vulnerable).

    Within each stratum: sort the case ids, shuffle with a fresh
    random.Random(seed), and put the first round(n * test_fraction) in
    "test". Deterministic for the same inputs, and each stratum's
    assignment does not depend on the other strata.
    """
    if not 0 <= test_fraction <= 1:
        raise ValueError(f"test_fraction must be in [0, 1], got {test_fraction}")
    split = {}
    for _, cases in sorted(_strata(answer_key).items()):
        cases = sorted(cases)
        random.Random(seed).shuffle(cases)
        n_test = round(len(cases) * test_fraction)
        split.update({c: "test" for c in cases[:n_test]})
        split.update({c: "dev" for c in cases[n_test:]})
    return dict(sorted(split.items()))


def stratum_counts(answer_key: dict[str, AnswerKeyEntry], split: dict[str, str]) -> dict:
    """{"category/vulnerable|safe": {"dev": n, "test": n}} for split.json."""
    counts = {}
    for (category, vulnerable), cases in sorted(_strata(answer_key).items()):
        name = f"{category}/{'vulnerable' if vulnerable else 'safe'}"
        counts[name] = {part: sum(split[c] == part for c in cases) for part in ("dev", "test")}
    return counts


def select_sample(alerts: list[NormalisedAlert], answer_key: dict[str, AnswerKeyEntry],
                  split: dict[str, str], cwe: str, size: int, seed: int
                  ) -> tuple[list[NormalisedAlert], dict]:
    """Return (sample alerts sorted by case_id, composition summary).

    Eligible: dev cases whose benchmark CWE is `cwe` and that have at
    least one CWE-matching alert. One alert per case: the matching alert
    with the lowest start_line, then rule_id. Cases are drawn with
    random.Random(seed) as evenly as possible between vulnerable and safe;
    if fewer than `size` qualify, all are returned and the shortfall is
    reported. The summary uses answer-key labels and is evaluation-side.
    """
    best: dict[str, NormalisedAlert] = {}
    for alert in alerts:
        case_id = alert["case_id"]
        entry = answer_key.get(case_id)
        if (entry is None or split.get(case_id) != "dev" or entry["cwe"] != cwe
                or not cwe_matches(alert["cwe"], entry["cwe"])):
            continue
        current = best.get(case_id)
        if current is None or (alert["start_line"], alert["rule_id"]) < (
                current["start_line"], current["rule_id"]):
            best[case_id] = alert

    vulnerable = sorted(c for c in best if answer_key[c]["vulnerable"])
    safe = sorted(c for c in best if not answer_key[c]["vulnerable"])
    n_vulnerable = min(len(vulnerable), size // 2)
    n_safe = min(len(safe), size - n_vulnerable)
    n_vulnerable = min(len(vulnerable), size - n_safe)   # odd size or short safe side

    rng = random.Random(seed)
    chosen = sorted(rng.sample(vulnerable, n_vulnerable) + rng.sample(safe, n_safe))
    sample = [{field: best[c][field] for field in _ALERT_FIELDS} for c in chosen]
    summary = {
        "cwe": cwe, "seed": seed, "requested": size, "selected": len(sample),
        "shortfall": max(0, size - len(sample)),
        "eligible_vulnerable": len(vulnerable), "eligible_safe": len(safe),
        "selected_vulnerable": n_vulnerable, "selected_safe": n_safe,
    }
    return sample, summary
