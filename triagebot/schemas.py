"""Shared contracts between components (all JSON-compatible):

- NormalisedAlert : ingest -> payload builder   (the shape Darren produces)
- ContextPayload  : payload builder -> review paths
- AgentReport     : one role's output (Analyst / Skeptic / Chair / single agent)
- Verdict         : review path -> validator -> evaluator

Keeping every interface in one module is what makes the components
independently testable and swappable.
"""
