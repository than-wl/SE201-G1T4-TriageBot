"""Deterministic validation gate (owner: Lisa).

Pure code, no LLM: checks the verdict's JSON shape and verifies every
citation (file, line, quote) against the actual source. Unsupported or
malformed output falls back to human_review with reasons — never silently
passed, never converted to false_positive.
"""
