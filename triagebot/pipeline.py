"""Main graph: wires ingest -> context payload -> review -> validate.

The only module that knows the orchestration style. Nodes themselves are
plain functions with no framework dependency, so the wiring can change
without touching any node.
"""
