"""Shared contracts between components (all JSON-compatible):

- NormalisedAlert : ingest -> payload builder   (the shape Darren produces)
- ContextPayload  : payload builder -> review paths
- AgentReport     : one role's output (Analyst / Skeptic / Chair / single agent)
- Verdict         : review path -> validator -> evaluator

Keeping every interface in one module is what makes the components
independently testable and swappable.
"""

from typing import Literal, TypedDict

VerdictLabel = Literal["true_positive", "false_positive", "human_review"]


class NormalisedAlert(TypedDict):
    case_id: str          # "BenchmarkTest00008"
    file: str             # repo-relative source path
    rule_id: str          # semgrep rule that fired
    cwe: str              # "CWE-89"; may be "" when unmapped
    start_line: int
    end_line: int
    message: str          # scanner message


class SourceContext(TypedDict):
    file: str
    lines: list[str]      # comment-stripped, numbered: "42: stmt.executeQuery(q);"


class HelperFacts(TypedDict):
    source_apis: list[str]
    sink_apis: list[str]
    string_concatenations: list[str]
    guards_or_constants: list[str]


class GuidanceChunk(TypedDict):
    doc: str              # cheat sheet name, e.g. "SQL_Injection_Prevention_Cheat_Sheet"
    section: str          # heading path, e.g. "Primary Defenses > Defense Option 1"
    text: str             # the chunk's plain text
    url: str              # canonical source URL for citation


class Guidance(TypedDict):
    source: str           # provenance, e.g. "OWASP Cheat Sheet Series"
    cwe_matched: bool     # False -> common/ only; forces human_review downstream
    chunks: list[GuidanceChunk]


class ContextPayload(TypedDict):
    alert: NormalisedAlert
    source: SourceContext
    facts: HelperFacts
    guidance: Guidance


class Citation(TypedDict):
    file: str
    line: int
    quote: str            # exact substring of that source line


class AgentReport(TypedDict):
    role: str             # "single" | "analyst" | "skeptic" | "chair"
    case_id: str
    verdict: VerdictLabel
    explanation: str
    citations: list[Citation]


class TriageResult(TypedDict):
    case_id: str
    verdict: VerdictLabel
    explanation: str
    citations: list[Citation]
