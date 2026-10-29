"""Shared contracts between components (all JSON-compatible):

- NormalisedAlert : ingest -> payload builder   (the shape Darren produces)
- ContextPayload  : payload builder -> review paths
- AgentReport     : one role's output (Analyst / Skeptic / Chair / single agent)
- Verdict         : review path -> validator -> evaluator
- AnswerKeyEntry  : EVALUATION ONLY; answer-key row, never sent to a model

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


class RelatedSource(TypedDict):
    file: str
    relationship: str
    lines: list[str]


class SourceContext(TypedDict):
    file: str
    lines: list[str]      # comment-stripped, numbered: "42: stmt.executeQuery(q);"
    related: list[RelatedSource]


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


class GuidanceRef(TypedDict):
    chunk_id: str         # which retrieved chunk, e.g. "SQL_..._Cheat_Sheet#003"
    doc: str              # cheat sheet name
    section: str          # heading path within the sheet
    url: str              # canonical source URL


class SecurityAnalysis(TypedDict):
    source: str
    sink: str
    reaches_sink: Literal["yes", "no", "uncertain"]
    protection: str
    protection_effective: Literal["yes", "no", "uncertain"]


class AgentReport(TypedDict):
    role: str             # "single" | "analyst" | "skeptic" | "chair"
    case_id: str
    verdict: VerdictLabel
    explanation: str
    citations: list[Citation]
    guidance: list[GuidanceRef]   # cheat-sheet chunks actually relied on
    analysis: SecurityAnalysis


class TriageResult(TypedDict):
    case_id: str
    verdict: VerdictLabel
    explanation: str
    citations: list[Citation]
    guidance: list[GuidanceRef]


# --- EVALUATION ONLY ------------------------------------------------------
# Answer-key shapes. Never part of a payload, prompt or LLM-side file.

class AnswerKeyEntry(TypedDict):
    category: str         # benchmark category, e.g. "sqli"
    cwe: str              # "CWE-89"
    vulnerable: bool      # answer key's "real vulnerability" column
