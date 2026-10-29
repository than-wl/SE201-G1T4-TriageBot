"""Context payload assembly: source window -> helper facts -> ContextPayload.

Three steps, one per function:
- strip_comments(): drop Java comments while keeping every character
  that remains line-aligned — citations and the validator reference
  original line numbers, so comment text becomes spaces (newlines kept).
- extract_facts(): pattern heuristics over the numbered lines; these
  are PROMPT HINTS telling reviewers where to look, never verdict logic.
- build_payload(): read the alert's file from the local benchmark
  checkout, window it around the alert, retrieve guidance, assemble.
"""

from pathlib import Path

from triagebot import config
from triagebot.nodes.context.source_context import build_source_context
from triagebot.schemas import ContextPayload, HelperFacts, NormalisedAlert

# --- comment stripping ---------------------------------------------------

def strip_comments(text: str) -> str:
    """Strip // and /* */ comments (string/char-literal aware).

    Comment characters are replaced by spaces so column positions and
    line numbers of the remaining code never shift.
    """
    out = []
    i, n = 0, len(text)
    state = "code"                      # code | line | block | string | char
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                out.append("  ")
                i += 2
                state = "line"
            elif c == "/" and nxt == "*":
                out.append("  ")
                i += 2
                state = "block"
            elif c in "\"'":
                out.append(c)
                i += 1
                state = "string" if c == '"' else "char"
            else:
                out.append(c)
                i += 1
        elif state == "line":
            if c == "\n":
                out.append("\n")        # keep the line break
                state = "code"
            else:
                out.append(" ")
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = "code"
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        else:                            # inside a string or char literal
            out.append(c)
            if c == "\\" and i + 1 < n:  # escape pair passes through intact
                out.append(text[i + 1])
                i += 2
                continue
            i += 1
            if (state == "string" and c == '"') or (state == "char" and c == "'"):
                state = "code"
    return "".join(out)

# --- helper facts ---------------------------------------------------------

_FACTS_MAX_PER_CATEGORY = 6

_SOURCE_PATTERNS = (
    "getParameter", "getHeader", "getCookies", "getQueryString",
    "readLine", "System.in", "Scanner(",
)
_SINK_PATTERNS = (
    "executeQuery", "executeUpdate", "executeBatch", "prepareStatement",
    "createStatement", "Runtime.exec", "ProcessBuilder", "eval(",
    "innerHTML",
)
_CONCAT_PATTERNS = (
    " + ", "String.format", "StringBuilder", "StringBuffer",
    ".append(", ".concat(",
)
_GUARD_PATTERNS = (
    "equals(", "equalsIgnoreCase", ".matches(", "startsWith(",
    "instanceof ", "allowlist", "whitelist", "isValid", "sanitiz",
)


def extract_facts(numbered_lines: list[str]) -> HelperFacts:
    """Collect up to _FACTS_MAX_PER_CATEGORY matching lines per category.

    Entries keep their "NN: " prefix so reviewers see the fact in place.
    """
    def collect(patterns: tuple[str, ...]) -> list[str]:
        found: list[str] = []
        for line in numbered_lines:
            low = line.lower()
            if any(p.lower() in low for p in patterns):
                found.append(line)
                if len(found) >= _FACTS_MAX_PER_CATEGORY:
                    break
        return found

    return {
        "source_apis": collect(_SOURCE_PATTERNS),
        "sink_apis": collect(_SINK_PATTERNS),
        "string_concatenations": collect(_CONCAT_PATTERNS),
        "guards_or_constants": collect(_GUARD_PATTERNS),
    }

# --- payload assembly -----------------------------------------------------

def build_payload(alert: NormalisedAlert, kb, benchmark_root=None) -> ContextPayload:
    """Assemble the ContextPayload for one alert (raises on bad input)."""
    root = benchmark_root or config.BENCHMARK_ROOT
    if not root:
        raise ValueError(
            "benchmark root unknown: pass benchmark_root=... or set BENCHMARK_ROOT"
        )
    root = Path(root).resolve()
    path = (root / alert["file"]).resolve()
    if not path.is_relative_to(root):                 # no path escape
        raise ValueError(f"alert file escapes benchmark root: {alert['file']}")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"benchmark source missing: {path}") from exc

    clean = strip_comments(text).splitlines()
    source = build_source_context(root, alert, clean)
    window = source["lines"]

    facts = extract_facts(window)
    guidance = kb.retrieve(
        alert, extra_terms=facts["source_apis"] + facts["sink_apis"]
    )
    return {"alert": alert, "source": source,
            "facts": facts, "guidance": guidance}
