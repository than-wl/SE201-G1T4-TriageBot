# TriageBot architecture

```mermaid
flowchart LR
    SRC["Java source<br/>OWASP Benchmark v1.2"] --> SG["Semgrep CE<br/>recorded or fresh scan"]
    SG --> NORM["Alert normaliser<br/>one record per finding"]

    subgraph EVIDENCE["Bounded evidence pack"]
      direction TB
      WINDOW["Alert source window"]
      RELATED["Referenced Java helpers and<br/>local shell or batch resources"]
      GUIDE["CWE guidance retrieval<br/>keyword or optional semantic SQLite index"]
    end
    NORM --> WINDOW
    NORM --> RELATED
    NORM --> GUIDE

    subgraph COUNCIL["LangGraph multi-agent council"]
      direction TB
      A["Analyst"]
      S["Skeptic"]
      C["Chair"]
      R["Consistency repair"]
      V["Deterministic schema and citation validator"]
      A --> C
      S --> C
      C --> R --> V
    end
    EVIDENCE --> A
    EVIDENCE --> S
    OR["OpenRouter<br/>google/gemini-3.8-flash<br/>temperature 0"] --> A
    OR --> S
    OR --> C
    OR --> R

    V --> TP["true_positive"]
    V --> FP["false_positive"]
    V --> HR["human_review<br/>safe fallback"]
    COUNCIL -. state .-> DB[("Optional SQLite checkpoints<br/>resume interrupted sessions")]

    subgraph EVAL["Evaluation only - labels never enter model prompts"]
      KEY["OWASP answer key"] --> SPLIT["Frozen held-out sample<br/>60 genuine + 60 safe across 6 CWEs"]
      SPLIT --> SCORE["Precision, recall, F1,<br/>per-CWE failures, cost and latency"]
    end
    SG -. scanner findings .-> SCORE
    V -. validated verdicts .-> SCORE
```

The editable Mermaid source used for exported images is
[`TriageBot_Architecture_Diagram.mmd`](TriageBot_Architecture_Diagram.mmd).

The answer key is isolated inside the evaluation harness. Runtime reviewers see
only the Semgrep alert, bounded project evidence, and retrieved security
guidance. A validated citation proves that quoted text exists; it does not prove
that the model's security interpretation is correct.
