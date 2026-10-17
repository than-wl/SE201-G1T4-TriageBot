"""Baseline review path (proposal condition B): one LLM call.

Receives the union of the evidence available to the two council specialists,
so the single-agent vs council comparison stays fair. Satisfies the same
interface as the council: ContextPayload in -> Verdict out.
"""
