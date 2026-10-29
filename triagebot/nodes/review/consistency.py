"""Check that a structured security analysis supports its verdict."""


def expected_verdict(analysis):
    if not isinstance(analysis, dict):
        return None
    reaches = analysis.get("reaches_sink")
    protected = analysis.get("protection_effective")
    if reaches == "yes" and protected == "no":
        return "true_positive"
    if reaches == "no" or protected == "yes":
        return "false_positive"
    if reaches in {"yes", "uncertain"} and protected in {"no", "uncertain"}:
        return "human_review"
    return None


def problem(report):
    expected = expected_verdict(report.get("analysis"))
    if expected is None or report.get("verdict") == expected:
        return None
    return (f"analysis implies {expected}, but the verdict is "
            f"{report.get('verdict')}")
