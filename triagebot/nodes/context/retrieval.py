"""CWE-keyed, keyword-ranked guidance retrieval over the local KB.

Stage 1: select documents matching the alert's CWE (fall back to common/).
Stage 2: rank chunks within those documents using terms derived from the
alert (rule id, sink APIs, message). No runtime web fetching; the KB is
populated once at setup time.
"""
