# OpenRouter smoke test

OpenRouter smoke-test status: PASS. Full TriageBot feasibility verification is still incomplete.

Test date: 2 October 2026, 19:14 Singapore time.

## Verified results

- Authenticated requests succeeded using the locally configured key; the key was not printed or stored in test artifacts.
- Requested and returned model: `google/gemini-3.8-flash`; provider: Google AI Studio.
- Five real Semgrep SQL-injection alerts from OWASP Benchmark Java v1.2: three genuine vulnerabilities and two false positives.
- Five of five responses parsed as JSON and passed the local shape/file/line/quote checks. All fifteen quoted source citations matched.
- Five of five verdicts matched the answer key for the same vulnerability category, SQL injection / CWE-89.
- Mean request latency: 9.87 seconds; observed range: 8.16-11.72 seconds.
- Usage: 6,375 input tokens + 1,373 completion tokens = 7,748 total tokens. Reported reasoning tokens: zero.
- Total API-reported inference cost: **US$0.00993**, below the US$0.10 test budget. This is inference usage, not a verified remaining account balance or credit-purchase fees.
- Offline checks rejected a fabricated `sanitizeSQL(param)` quote, an unknown file/line, and an invalid JSON object.

| Benchmark case | Expected verdict | Model verdict | Validated citations | Latency (s) | Reported cost (US$) |
|---|---|---|---|---:|---:|
| 00008 | True positive | True positive | Pass | 11.222 | 0.00191925 |
| 00018 | True positive | True positive | Pass | 11.716 | 0.00181800 |
| 00024 | True positive | True positive | Pass | 8.165 | 0.00181500 |
| 00104 | False positive | False positive | Pass | 9.457 | 0.00213900 |
| 00105 | False positive | False positive | Pass | 8.783 | 0.00223875 |

The model recognized that a prepared/callable statement does not fix SQL already constructed by unsafe concatenation. It also evaluated constant branches in the two false positives rather than accepting the scanner's taint report unchanged.

## Method and reproducibility

The existing Semgrep JSON records version 1.178.0, 1,909 findings, 2,766 scanned files, and zero recorded errors. These are scanner execution counts, **not** correctness or recall metrics. Selected alerts use `java.lang.security.audit.sqli.tainted-sql-from-http-request.tainted-sql-from-http-request`. Each selected case's answer-key category and CWE match the scanner category; filename matching alone is insufficient for evaluating other findings.

Inputs consisted of scanner metadata, the actual Java source with preserved line numbers, and a short manually curated security-guidance summary. All Java comments were stripped, including branch-hint comments. The answer key was used to select a mixed sample and for evaluation, but labels and the CSV were never sent to OpenRouter. Test names remain visible; memorization cannot be ruled out.

The model catalogue advertised structured outputs. Requests used strict JSON Schema, `provider.require_parameters=true`, temperature zero, minimal reasoning effort, and `max_tokens=2048`. Implementation follows the [OpenRouter structured-output documentation](https://openrouter.ai/docs/guides/features/structured-outputs) and [reasoning-token documentation](https://openrouter.ai/docs/guides/best-practices/reasoning-tokens). The curated SQLi guidance is based on the [OWASP prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html); it is not evidence that RAG retrieval works.

The script reuses installed python-dotenv and Python's standard library; no new dependencies were added. Credentials are loaded locally and used only in the HTTPS authorization header. Saved request artifacts contain the prompt and model settings, not that header. Responses and usage are saved separately. Requests are sequential, with no automatic retries. A byte-count-based conservative input estimate plus the completion allowance reserves US$0.068685 for this run; this is a client-side estimate, not a server-side billing cap.

Offline verification (no network requests or credit spending):

```powershell
& '.\.verification-venv\Scripts\python.exe' '.\verification\openrouter_smoke.py' --self-test
```

Reproduce the five paid calls (uses credits and creates a new timestamped artifact directory):

```powershell
& '.\.verification-venv\Scripts\python.exe' '.\verification\openrouter_smoke.py'
```

Evidence: `Context/tmp/openrouter-smoke/20261002T111410Z/results.json`, plus the five saved request/response pairs in the same directory. Source hashes, provider/model identifiers, tokens, reported costs, outputs, and evaluation labels are recorded in the results file.

## Proposal-safe conclusion and remaining work

Safe wording: "An initial feasibility smoke test successfully ran Semgrep on OWASP Benchmark Java and used Gemini 3.8 Flash through OpenRouter to triage five category-aligned SQL-injection alerts. All five responses were valid structured JSON with matching source citations and matched benchmark labels, at a reported total inference cost of US$0.00993. This small selected sample demonstrates integration feasibility, not general accuracy."

Do not claim the 95% genuine-finding retention or 25% false-positive-removal targets have been achieved. This was one run, one category, and five deliberately selected cases. No statistical comparison or reliability estimate is justified.

Next handoff gates remain: common-evidence/helper lookup checks, actual security-guidance retrieval, a same-model single-agent versus Analyst/Skeptic/Chair comparison with equal evidence access, and a broader deterministic validator with conservative human-review fallback. The present citation check verifies only JSON shape and quote existence, not the truth of reasoning or completeness of a source-to-sink path. It does not implement automatic suppression. The final full feasibility report and proposal revision should distinguish these remaining gates from the two completed scanner/API smoke tests.
