"""Evaluation harness (owner: Bradley).

Joins saved run results with the hidden answer key and computes the
checkpoint metrics (retained / removed / wrongly dismissed / human-review
rate, latency, cost). Runs outside the LLM-facing pipeline: the answer
key enters only here and never appears in any payload or prompt.
"""
