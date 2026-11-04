# Evaluation evidence

This folder contains the raw, reviewable evidence behind the committed summary
reports. The files are unchanged copies of the recorded local outputs.

## What is included

- `fresh-120/`: the 2 November generalisation sample, manifest, raw council
  results, validated results and evaluation. This run used the latest fixed
  council. It did not rerun the single-agent baseline, so there is no `B` file.
- `comparison-66/`: the complete 66-case controlled-comparison folder, including
  the frozen sample and every saved council/validated run.
- `semgrep/semgrep-owasp-combined.json`: Semgrep 1.178.0 output for the combined
  `p/java` and `p/security-audit` scan.
- `original-final-120/`: the earlier frozen 120-case experiment, including its
  saved B (single agent), C (council), D (validated council) and evaluation files.
- `checkpoint-100/`: the checkpoint sample and its saved B/C/D result files.
- `prior-samples/`: copies needed to reproduce the fresh-run overlap audit.

## Fresh 120-case construction

The exact one-off builder used on 2 November is preserved as
`fresh-120/build_sample_used.py`. It selected:

- 24 each from CWE-22, CWE-78, CWE-79 and CWE-89;
- 12 each from CWE-501 and CWE-643;
- half genuine and half safe cases within every category.

The builder excluded the 120-case original-final sample and the 66-case
comparison sample during construction: **186 cases**. The command used was:

```powershell
.\.verification-venv\Scripts\python.exe Context/tmp/fresh-120-sample-builder.py
```

The resulting label-free `selected_alerts.json` has SHA-256
`d06d33baada754380d2f5891c8381024fe2f01c4fd984f09b41543bccd2959db`.

After selection, we audited it against every relevant prior sample or model
call: 100 checkpoint cases + 120 original-final cases + 66 comparison cases +
the additional OpenRouter smoke case `BenchmarkTest00105` = **287 unique prior
cases**. The overlap was zero. Recreate and verify that audit with:

```powershell
python evidence/fresh-120/audit_prior_cases.py
```

The generated `fresh-120/prior_case_audit.json` contains the complete sorted
287-case list, source counts, fresh sample hash and overlap result.

The paid council was run resumably using the preserved output files. The command
used was:

```powershell
$env:PYTHONPATH='.'
.\.verification-venv\Scripts\python.exe -u Context/tmp/fresh-120-runner.py
```

## 66-case comparison construction

The comparison sample was frozen with the tracked builder:

```powershell
python verification/prepare_comparison_sample.py `
  --semgrep Context/tmp/final/semgrep-owasp-combined.json `
  --answer-key Context/tmp/BenchmarkJava/expectedresults-1.2.csv `
  --prior-sample Context/tmp/final/selected_alerts.json `
  --out Context/tmp/comparison
```

The answer key was used only for balanced sample selection and offline scoring;
labels were not included in model prompts or `selected_alerts.json`.

## Safety and interpretation

- No OpenRouter key, authentication header, user-specific absolute path or `.env`
  value is present in these files.
- Model result files contain bounded excerpts from the public OWASP Benchmark.
- A B/C/D filename means single agent / raw council / validated council.
- Missing B files mean that configuration was not run; they are not missing data.
- These artifacts are evidence, not inputs required for normal TriageBot use.
