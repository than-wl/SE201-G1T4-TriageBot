# SE201 G1T4 (TriageBot)

Evidence-grounded triage of static security-scanner alerts.

This repository currently contains the reproducibility checks for the OWASP Benchmark and OpenRouter feasibility experiments. The private `Context/` folder contains project notes, source material, benchmark data, reports, and generated evidence; it is intentionally excluded from Git.

## Offline check

```powershell
& '.\.verification-venv\Scripts\python.exe' '.\verification\openrouter_smoke.py' --self-test
```

The online checks require a local `OPENROUTER_API_KEY` in `.env`. Never commit credentials or generated context artifacts.
