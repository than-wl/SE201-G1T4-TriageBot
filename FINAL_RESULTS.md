# TriageBot Final Results

## What did we test?

Semgrep scans source code for possible security problems, but some of its
warnings are false alarms. TriageBot uses AI to help sort each warning into:

- a real vulnerability;
- a false alarm; or
- something a human should check.

We tested TriageBot on **120 previously unseen OWASP Benchmark cases** across
five vulnerability types. Half were real vulnerabilities and half were false
alarms.

We compared four approaches:

1. Semgrep alone;
2. one AI agent;
3. an AI council consisting of an Analyst, Skeptic and Chair; and
4. the AI council followed by automatic evidence validation.

The model was `google/gemini-3.8-flash`. We fixed the test cases and settings
before running the final test and did not tune the system using its results.

## Main results

| Approach | Precision | Recall | F1 | False alarms removed | Real vulnerabilities wrongly removed | Sent to a human |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Semgrep alone | 50.0% | 100.0% | 66.7% | 0 of 60 | 0 of 60 | 0 |
| One AI agent | 83.3% | 83.3% | 83.3% | 50 of 60 | 10 of 60 | 12 |
| AI council | **89.1%** | 95.0% | **91.9%** | **53 of 60** | 3 of 60 | 9 |
| Validated council | 85.3% | **96.7%** | 90.6% | 50 of 60 | **2 of 60** | 26 |

Precision means: when the system kept a warning, how often was it genuinely
dangerous? Recall means: how many genuine vulnerabilities did the system avoid
incorrectly removing? F1 combines precision and recall into one score.

## What went well?

- The AI council performed best overall, reaching **91.9% F1**.
- It removed **53 of the 60 false alarms**, greatly reducing manual work.
- It kept or escalated **57 of the 60 real vulnerabilities**.
- Validation made the system safer by reducing wrongly removed real
  vulnerabilities from three to two.
- Repeating five selected cases produced the same verdicts each time.
- A broader Semgrep configuration improved full-benchmark recall from
  **70.3% to 88.3%**, meaning fewer vulnerabilities were missed before reaching
  TriageBot.

## What did not go well?

- The council still wrongly removed **3 real vulnerabilities**. Therefore,
  TriageBot is not safe enough to dismiss warnings automatically.
- Validation was safer, but it sent **26 of 120 cases** to humans, reducing the
  amount of work saved.
- Performance differed by vulnerability type. Command injection produced the
  most dangerous mistakes, while LDAP injection had the most false alarms
  remaining.
- Some cases needed helper-method code that was outside the supplied source
  window, so the AI did not always have enough context.

The biggest weakness appeared in the initial single-agent mutation test. We
changed five safe code examples so that they became vulnerable. The single
agent changed **0 out of 5** verdicts correctly. Running the same five declared
development pairs through the council later classified all five vulnerable
mutations correctly, showing that the result depended strongly on the review
architecture.

## Cost

- Final one-agent and council evaluation: **US$1.918870**
- Mutation and repeat checks: **US$0.093335**

Validation reused the council output and did not require additional AI calls.

## What improved afterward?

We added bounded related-source retrieval, CWE-specific review checklists,
structured verdict-reasoning consistency checks and targeted validation repair.
We then compared the old and improved validated pipelines on the same **66 new,
unused cases**, with the same Gemini 3.8 Flash model and settings:

| Validated result | Old pipeline | Improved pipeline |
| --- | ---: | ---: |
| Precision | 90.9% | **100.0%** |
| Recall | 90.9% | **93.9%** |
| F1 | 90.9% | **96.9%** |
| False alarms removed | 30 of 33 | **33 of 33** |
| Real vulnerabilities wrongly removed | 3 of 33 | **2 of 33** |
| Sent to a human | 11 of 66 | **1 of 66** |

The improved run cost about **US$0.13 more** and took about **three seconds
longer per case**. Two command-injection cases were still wrongly dismissed,
so the improvement is meaningful but does not make automatic suppression safe.

## Final conclusion

TriageBot is promising as a **decision-support tool**. It can remove many
Semgrep false alarms and reduce the amount of manual review.

However, it is **not ready to automatically suppress security warnings**. A
human must still review its evidence before closing a finding. The next
technical priority is indirect command-injection context: the two remaining
misses passed attacker-controlled environment variables to scripts that were
outside the retrieved Java source graph.

These results come from a synthetic Java benchmark and five vulnerability
types. They should not be treated as proof of performance on real production
projects.
