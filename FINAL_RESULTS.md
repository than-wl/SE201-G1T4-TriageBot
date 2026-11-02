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

We later fixed that specific weakness by following referenced Java helpers into
local shell and batch resources. On the same 66-case **regression set**, the
merged system improved from **95.4% to 98.5% F1**, and real vulnerabilities
wrongly removed fell from **2 to 0**. False-alarm removal stayed at 32 of 33 and
human review fell from 3 cases to 2. This cost about **US$0.14 more**, took about
2.9 seconds longer per case, and used 21.8% more prompt tokens. Because these
cases informed the fix, this is regression evidence rather than a new unseen
evaluation.

## Did the latest version work on new cases?

Yes. We froze another **120 previously unused cases** after the fix: 60 genuine
vulnerabilities and 60 false alarms across six CWE categories. They had zero
overlap with the 287 cases previously selected or sent to a model. The answer
key was used to balance the sample, but was withheld until all model calls had
finished.

| Latest version | Precision | Recall | F1 | False alarms removed | Real vulnerabilities wrongly removed | Sent to a human |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AI council | **93.8%** | **100.0%** | **96.8%** | **56 of 60** | **0 of 60** | 2 of 120 |
| Validated council | 85.7% | **100.0%** | 92.3% | 50 of 60 | **0 of 60** | 14 of 120 |

This fresh test supports the safety improvement: neither configuration
wrongly removed a genuine vulnerability. The raw council was more useful
overall. Validation safely escalated every CWE-501 case because the knowledge
base has no CWE-501 guidance, and escalated two other cases with missing
citations. This explains 14 human reviews and the lower validated precision/F1;
it is a guidance-coverage limitation, not evidence that unsafe results were
accepted.

The run cost **US$1.922363**, averaged **24.676 seconds per case**, and had a
maximum latency of **113.577 seconds**. It is one frozen benchmark run, so it
supports generalisation but does not prove production performance.

## Final conclusion

TriageBot is promising as a **decision-support tool**. It can remove many
Semgrep false alarms and reduce the amount of manual review.

However, it is **not ready to automatically suppress security warnings**. A
human must still review its evidence before closing a finding. The next
technical priorities are adding guidance for uncovered CWE categories and
reliable handling of occasional missing-citation failures without weakening
validation.

These results come from a synthetic Java benchmark. They should not be treated
as proof of performance on real production projects.
