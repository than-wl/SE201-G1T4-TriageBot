"""Binary classification metrics over benchmark cases (pure, no I/O).

This is the single metrics module intended to be shared by the scanner
baseline (ingest/run.py) and the evaluation harness, so every table in
the report computes TP/FP/FN/TN and precision/recall/F1 the same way.

A prediction is True when a case is called vulnerable. A label is True
when the answer key marks the case as a real vulnerability.

NOT DECIDED YET: how a TriageBot "human_review" verdict maps onto these
binary predictions (count it as vulnerable, exclude it, or report it
separately). Callers must resolve that before passing predictions in;
this module accepts only True/False.
"""


def confusion(predictions: dict[str, bool], labels: dict[str, bool]) -> dict[str, int]:
    """{"tp", "fp", "fn", "tn"}; raises if the two case sets differ."""
    if set(predictions) != set(labels):
        missing = sorted(set(labels) - set(predictions))[:5]
        extra = sorted(set(predictions) - set(labels))[:5]
        raise ValueError(f"case sets differ: missing predictions {missing}, unlabelled {extra}")
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for case_id, predicted in predictions.items():
        if type(predicted) is not bool or type(labels[case_id]) is not bool:
            raise ValueError(f"{case_id}: predictions and labels must be True/False")
        actual = labels[case_id]
        counts[("t" if predicted == actual else "f") + ("p" if predicted else "n")] += 1
    return counts


def _ratio(part: int, whole: int) -> float | None:
    return part / whole if whole else None


def precision_recall_f1(counts: dict[str, int]) -> dict[str, float | None]:
    """Each value is None when its denominator is 0.

    F1 is None whenever precision or recall is None; otherwise it is
    2TP / (2TP + FP + FN), which is 0.0 when both are 0.
    """
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = None if precision is None or recall is None else _ratio(2 * tp, 2 * tp + fp + fn)
    return {"precision": precision, "recall": recall, "f1": f1}


def _row(predictions, labels):
    counts = confusion(predictions, labels)
    return {"cases": len(predictions), **counts, **precision_recall_f1(counts)}


def by_category(predictions: dict[str, bool], answer_key: dict) -> dict[str, dict]:
    """Per-category rows (sorted by name) plus an "overall" row.

    answer_key: {case_id: {"category", "vulnerable", ...}}. Each row holds
    cases, tp, fp, fn, tn, precision, recall, f1.
    """
    labels = {case_id: entry["vulnerable"] for case_id, entry in answer_key.items()}
    confusion(predictions, labels)                      # same case sets, or raise
    rows = {}
    for category in sorted({entry["category"] for entry in answer_key.values()}):
        cases = [c for c, entry in answer_key.items() if entry["category"] == category]
        rows[category] = _row({c: predictions[c] for c in cases}, {c: labels[c] for c in cases})
    rows["overall"] = _row(predictions, labels)
    return rows
