# Semantic set-up check: retrieval quality (free, no model calls)

Generated 2026-11-08T16:34:49+00:00 by `python verification/semantic_setup_check.py --phase score`. Code: commit `c0af72cdac06`.
MITRE CWE catalogue 5.0 (zip SHA-256 `bcda44c9abf6…`), embedding model `BAAI/bge-small-en-v1.5`, `scope.json` SHA-256 `acfbe052644b…`, label files `7d304c17e7e3…` (original) and `4c74d5de4343…` (added). Budget 4,000 characters, at most 6 chunks.

Configurations: `original` is all five rules off (decision 21); `+R1` .. `+R5` are original plus one rule; `improved` is the `semantic` profile (all five on). This measures topic relevance of the guidance, not verdict accuracy.

Grades: 2 = guidance about this weakness, 1 = adjacent, 0 = not relevant. Precision counts grade 2 only. The search ranking is the top 6 searched chunks by cosine, ignoring the budget (the MITRE chunk is attached by ID and never searched). The pack is what `retrieve()` returns. The MITRE chunk is not graded, so the pack's grade counts and grade-2 characters cover OWASP chunks only; total characters include it.

**Wrong platform** counts chunks from sheets that `scope.json` tags with a platform other than Java, or excludes as retired or as the attack catalogue. The rubric grades topic, not platform (a FastAPI chunk about SQL injection is graded 2), so rule R3's effect shows in this column, not in precision.

## Part A: the 9 scan CWEs (macro average over CWEs)

| Configuration | P@3 | P@6 | Mean grade | MITRE in pack | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search (total) | Wrong platform, pack (total) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `original` | 0.63 | 0.54 | 1.33 | 0 of 9 | 4.1 | 2.4 | 3.4 | 3,203 | 2,173 | 5 | 3 |
| `+R1` | 0.70 | 0.69 | 1.59 | 0 of 9 | 4.2 | 3.2 | 4.0 | 3,281 | 2,598 | 8 | 6 |
| `+R2` | 0.63 | 0.54 | 1.33 | 9 of 9 | 2.9 | 1.6 | 2.6 | 3,392 | 1,475 | 5 | 2 |
| `+R3` | 0.56 | 0.48 | 1.24 | 0 of 9 | 4.2 | 2.2 | 3.4 | 3,208 | 1,958 | 0 | 0 |
| `+R4` | 0.63 | 0.56 | 1.39 | 0 of 9 | 4.3 | 2.6 | 3.7 | 3,373 | 2,202 | 6 | 4 |
| `+R5` | 0.63 | 0.54 | 1.33 | 0 of 9 | 4.1 | 2.4 | 3.4 | 3,203 | 2,173 | 5 | 3 |
| `improved` | 0.67 | 0.57 | 1.44 | 9 of 9 | 3.1 | 1.8 | 2.9 | 3,172 | 1,135 | 0 | 0 |

`+R5` gives the same rankings and packs as `original`: yes (expected, since every scan CWE has a valid record).

## Part A per CWE: original vs improved

Each cell is original → improved.

| CWE | P@3 | P@6 | Mean grade | MITRE chars | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 0.67 → 0.00 | 0.50 → 0.00 | 1.33 → 0.50 | 0 → 1290 | 3 → 3 | 2 → 0 | 3 → 2 | 3,357 → 3,969 | 1,928 → 0 | 3 → 0 | 2 → 0 |
| CWE-78 | 0.67 → 1.00 | 0.50 → 0.83 | 1.00 → 1.83 | 0 → 1376 | 5 → 2 | 3 → 2 | 3 → 2 | 3,765 → 2,740 | 2,665 → 1,364 | 0 → 0 | 0 → 0 |
| CWE-79 | 0.33 → 1.00 | 0.33 → 1.00 | 0.83 → 2.00 | 0 → 1458 | 6 → 5 | 2 → 5 | 3 → 5 | 2,061 → 3,776 | 1,361 → 2,318 | 1 → 0 | 1 → 0 |
| CWE-89 | 0.67 → 0.67 | 0.67 → 0.67 | 1.67 → 1.67 | 0 → 1343 | 2 → 1 | 1 → 0 | 2 → 1 | 2,256 → 2,965 | 634 → 0 | 1 → 0 | 0 → 0 |
| CWE-90 | 1.00 → 1.00 | 1.00 → 1.00 | 2.00 → 2.00 | 0 → 1444 | 3 → 2 | 3 → 2 | 3 → 2 | 3,731 → 3,976 | 3,731 → 2,532 | 0 → 0 | 0 → 0 |
| CWE-326 | 0.33 → 0.33 | 0.33 → 0.33 | 1.00 → 1.00 | 0 → 309 | 5 → 5 | 2 → 2 | 4 → 4 | 2,525 → 2,834 | 1,653 → 1,653 | 0 → 0 | 0 → 0 |
| CWE-328 | 1.00 → 1.00 | 0.50 → 0.50 | 1.33 → 1.33 | 0 → 1468 | 3 → 1 | 3 → 1 | 3 → 1 | 3,881 → 3,256 | 3,881 → 1,788 | 0 → 0 | 0 → 0 |
| CWE-501 | 0.00 → 0.00 | 0.00 → 0.00 | 0.83 → 0.83 | 0 → 94 | 4 → 4 | 0 → 0 | 4 → 4 | 3,554 → 3,648 | 0 → 0 | 0 → 0 | 0 → 0 |
| CWE-643 | 1.00 → 1.00 | 1.00 → 0.83 | 2.00 → 1.83 | 0 → 564 | 6 → 5 | 6 → 4 | 6 → 5 | 3,700 → 1,383 | 3,700 → 559 | 0 → 0 | 0 → 0 |

## Part A per CWE, every configuration

**`original`**

| CWE | P@3 | P@6 | Mean grade | MITRE | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 0.67 | 0.50 | 1.33 | no | 3 | 2 | 3 | 3,357 | 1,928 | 3 | 2 |
| CWE-78 | 0.67 | 0.50 | 1.00 | no | 5 | 3 | 3 | 3,765 | 2,665 | 0 | 0 |
| CWE-79 | 0.33 | 0.33 | 0.83 | no | 6 | 2 | 3 | 2,061 | 1,361 | 1 | 1 |
| CWE-89 | 0.67 | 0.67 | 1.67 | no | 2 | 1 | 2 | 2,256 | 634 | 1 | 0 |
| CWE-90 | 1.00 | 1.00 | 2.00 | no | 3 | 3 | 3 | 3,731 | 3,731 | 0 | 0 |
| CWE-326 | 0.33 | 0.33 | 1.00 | no | 5 | 2 | 4 | 2,525 | 1,653 | 0 | 0 |
| CWE-328 | 1.00 | 0.50 | 1.33 | no | 3 | 3 | 3 | 3,881 | 3,881 | 0 | 0 |
| CWE-501 | 0.00 | 0.00 | 0.83 | no | 4 | 0 | 4 | 3,554 | 0 | 0 | 0 |
| CWE-643 | 1.00 | 1.00 | 2.00 | no | 6 | 6 | 6 | 3,700 | 3,700 | 0 | 0 |

**`+R1`**

| CWE | P@3 | P@6 | Mean grade | MITRE | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 0.67 | 0.67 | 1.67 | no | 2 | 2 | 2 | 2,803 | 2,803 | 4 | 2 |
| CWE-78 | 1.00 | 1.00 | 2.00 | no | 6 | 6 | 6 | 3,454 | 3,454 | 1 | 1 |
| CWE-79 | 0.67 | 0.83 | 1.67 | no | 6 | 5 | 5 | 2,913 | 2,813 | 1 | 1 |
| CWE-89 | 0.67 | 0.83 | 1.83 | no | 3 | 2 | 3 | 3,659 | 2,037 | 1 | 1 |
| CWE-90 | 1.00 | 1.00 | 2.00 | no | 3 | 3 | 3 | 3,052 | 3,052 | 1 | 1 |
| CWE-326 | 0.33 | 0.33 | 1.00 | no | 5 | 2 | 4 | 2,525 | 1,653 | 0 | 0 |
| CWE-328 | 1.00 | 0.50 | 1.33 | no | 3 | 3 | 3 | 3,881 | 3,881 | 0 | 0 |
| CWE-501 | 0.00 | 0.00 | 0.83 | no | 4 | 0 | 4 | 3,554 | 0 | 0 | 0 |
| CWE-643 | 1.00 | 1.00 | 2.00 | no | 6 | 6 | 6 | 3,692 | 3,692 | 0 | 0 |

**`+R2`**

| CWE | P@3 | P@6 | Mean grade | MITRE | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 0.67 | 0.50 | 1.33 | 1290 chars | 2 | 1 | 2 | 3,712 | 993 | 3 | 1 |
| CWE-78 | 0.67 | 0.50 | 1.00 | 1376 chars | 2 | 2 | 2 | 3,532 | 2,156 | 0 | 0 |
| CWE-79 | 0.33 | 0.33 | 0.83 | 1458 chars | 5 | 2 | 3 | 3,243 | 1,361 | 1 | 1 |
| CWE-89 | 0.67 | 0.67 | 1.67 | 1343 chars | 2 | 1 | 2 | 3,599 | 634 | 1 | 0 |
| CWE-90 | 1.00 | 1.00 | 2.00 | 1444 chars | 2 | 2 | 2 | 3,860 | 2,416 | 0 | 0 |
| CWE-326 | 0.33 | 0.33 | 1.00 | 309 chars | 5 | 2 | 4 | 2,834 | 1,653 | 0 | 0 |
| CWE-328 | 1.00 | 0.50 | 1.33 | 1468 chars | 1 | 1 | 1 | 3,256 | 1,788 | 0 | 0 |
| CWE-501 | 0.00 | 0.00 | 0.83 | 94 chars | 4 | 0 | 4 | 3,648 | 0 | 0 | 0 |
| CWE-643 | 1.00 | 1.00 | 2.00 | 564 chars | 3 | 3 | 3 | 2,840 | 2,276 | 0 | 0 |

**`+R3`**

| CWE | P@3 | P@6 | Mean grade | MITRE | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 0.00 | 0.00 | 0.50 | no | 4 | 0 | 3 | 3,003 | 0 | 0 | 0 |
| CWE-78 | 0.67 | 0.50 | 1.00 | no | 5 | 3 | 3 | 3,765 | 2,665 | 0 | 0 |
| CWE-79 | 0.33 | 0.33 | 0.83 | no | 6 | 2 | 3 | 2,461 | 1,361 | 0 | 0 |
| CWE-89 | 0.67 | 0.67 | 1.67 | no | 2 | 1 | 2 | 2,256 | 634 | 0 | 0 |
| CWE-90 | 1.00 | 1.00 | 2.00 | no | 3 | 3 | 3 | 3,731 | 3,731 | 0 | 0 |
| CWE-326 | 0.33 | 0.33 | 1.00 | no | 5 | 2 | 4 | 2,525 | 1,653 | 0 | 0 |
| CWE-328 | 1.00 | 0.50 | 1.33 | no | 3 | 3 | 3 | 3,881 | 3,881 | 0 | 0 |
| CWE-501 | 0.00 | 0.00 | 0.83 | no | 4 | 0 | 4 | 3,554 | 0 | 0 | 0 |
| CWE-643 | 1.00 | 1.00 | 2.00 | no | 6 | 6 | 6 | 3,700 | 3,700 | 0 | 0 |

**`+R4`**

| CWE | P@3 | P@6 | Mean grade | MITRE | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 0.67 | 0.67 | 1.67 | no | 4 | 3 | 4 | 3,618 | 2,189 | 4 | 3 |
| CWE-78 | 0.67 | 0.50 | 1.00 | no | 5 | 3 | 3 | 3,765 | 2,665 | 0 | 0 |
| CWE-79 | 0.33 | 0.50 | 1.17 | no | 6 | 3 | 4 | 1,917 | 1,493 | 1 | 1 |
| CWE-89 | 0.67 | 0.67 | 1.67 | no | 2 | 1 | 2 | 2,256 | 634 | 1 | 0 |
| CWE-90 | 1.00 | 1.00 | 2.00 | no | 3 | 3 | 3 | 3,731 | 3,731 | 0 | 0 |
| CWE-326 | 0.33 | 0.33 | 1.00 | no | 6 | 2 | 4 | 3,805 | 1,653 | 0 | 0 |
| CWE-328 | 1.00 | 0.50 | 1.33 | no | 3 | 3 | 3 | 3,881 | 3,881 | 0 | 0 |
| CWE-501 | 0.00 | 0.00 | 0.83 | no | 4 | 0 | 4 | 3,554 | 0 | 0 | 0 |
| CWE-643 | 1.00 | 0.83 | 1.83 | no | 6 | 5 | 6 | 3,831 | 3,571 | 0 | 0 |

**`+R5`**

| CWE | P@3 | P@6 | Mean grade | MITRE | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 0.67 | 0.50 | 1.33 | no | 3 | 2 | 3 | 3,357 | 1,928 | 3 | 2 |
| CWE-78 | 0.67 | 0.50 | 1.00 | no | 5 | 3 | 3 | 3,765 | 2,665 | 0 | 0 |
| CWE-79 | 0.33 | 0.33 | 0.83 | no | 6 | 2 | 3 | 2,061 | 1,361 | 1 | 1 |
| CWE-89 | 0.67 | 0.67 | 1.67 | no | 2 | 1 | 2 | 2,256 | 634 | 1 | 0 |
| CWE-90 | 1.00 | 1.00 | 2.00 | no | 3 | 3 | 3 | 3,731 | 3,731 | 0 | 0 |
| CWE-326 | 0.33 | 0.33 | 1.00 | no | 5 | 2 | 4 | 2,525 | 1,653 | 0 | 0 |
| CWE-328 | 1.00 | 0.50 | 1.33 | no | 3 | 3 | 3 | 3,881 | 3,881 | 0 | 0 |
| CWE-501 | 0.00 | 0.00 | 0.83 | no | 4 | 0 | 4 | 3,554 | 0 | 0 | 0 |
| CWE-643 | 1.00 | 1.00 | 2.00 | no | 6 | 6 | 6 | 3,700 | 3,700 | 0 | 0 |

**`improved`**

| CWE | P@3 | P@6 | Mean grade | MITRE | OWASP chunks | Grade 2 | Grade ≥1 | Pack chars | Grade-2 chars | Wrong platform, search | Wrong platform, pack |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-22 | 0.00 | 0.00 | 0.50 | 1290 chars | 3 | 0 | 2 | 3,969 | 0 | 0 | 0 |
| CWE-78 | 1.00 | 0.83 | 1.83 | 1376 chars | 2 | 2 | 2 | 2,740 | 1,364 | 0 | 0 |
| CWE-79 | 1.00 | 1.00 | 2.00 | 1458 chars | 5 | 5 | 5 | 3,776 | 2,318 | 0 | 0 |
| CWE-89 | 0.67 | 0.67 | 1.67 | 1343 chars | 1 | 0 | 1 | 2,965 | 0 | 0 | 0 |
| CWE-90 | 1.00 | 1.00 | 2.00 | 1444 chars | 2 | 2 | 2 | 3,976 | 2,532 | 0 | 0 |
| CWE-326 | 0.33 | 0.33 | 1.00 | 309 chars | 5 | 2 | 4 | 2,834 | 1,653 | 0 | 0 |
| CWE-328 | 1.00 | 0.50 | 1.33 | 1468 chars | 1 | 1 | 1 | 3,256 | 1,788 | 0 | 0 |
| CWE-501 | 0.00 | 0.00 | 0.83 | 94 chars | 4 | 0 | 4 | 3,648 | 0 | 0 | 0 |
| CWE-643 | 1.00 | 0.83 | 1.83 | 564 chars | 5 | 4 | 5 | 1,383 | 559 | 0 | 0 |

## CWE-79 "CSS" check

CWE-79's alternate terms include "CSS", MITRE's old abbreviation for cross-site scripting. Below: every chunk in CWE-79's search ranking or pack under `+R1` or `improved` whose text mentions CSS or style sheets (a mechanical match; the excerpt shows which sense is meant).

| Chunk | Section | Grade | Also under original | Seen in | Excerpt |
| --- | --- | ---: | --- | --- | --- |
| `DOM_based_XSS_Prevention_Cheat_Sheet#001` | Introduction | 2 | no | +R1 ranking; +R1 pack | ... ls for the actual data flow and output context. When a browser is rendering HTML and any other associated content like CSS or JavaScript, it identifies various rendering contexts for the different kinds of input and follows different rules fo ... |
| `DOM_based_XSS_Prevention_Cheat_Sheet#001.1` | Introduction | 2 | no | improved ranking; improved pack | ... ls for the actual data flow and output context. When a browser is rendering HTML and any other associated content like CSS or JavaScript, it identifies various rendering contexts for the different kinds of input and follows different rules fo ... |
| `Java_Security_Cheat_Sheet#018` | Specific Injection types > HTML/JavaScript/CSS > How to prevent | 2 | yes | +R1 ranking; +R1 pack; improved ranking; improved pack | ... rules; it does not replace these XSS controls. See the XSS Prevention Cheat Sheet for HTML, attribute, JavaScript, and CSS context requirements. |

## Part B: weaknesses outside the benchmark (no grading needed)

Fixed in advance: CWEs not in the scan for which the knowledge base has a sheet dedicated to that one weakness. "First rank" is the rank of the sheet's first chunk in the full search ranking. "In the map?" is for context only.

**Expected sheet in pack: 9 of 10 (original) vs 10 of 10 (improved).**

| CWE | Name | Expected sheet | In the map? | Original: in pack | first rank | chunks from it | Improved: in pack | first rank | chunks from it |
| --- | --- | --- | --- | --- | ---: | ---: | --- | ---: | ---: |
| CWE-918 | Server-Side Request Forgery | `Server_Side_Request_Forgery_Prevention_Cheat_Sheet` | yes | no | 6 | 0 of 3 | yes | 2 | 1 of 2 |
| CWE-611 | Improper Restriction of XML External Entity Reference | `XML_External_Entity_Prevention_Cheat_Sheet` | yes | yes | 2 | 1 of 4 | yes | 2 | 3 of 5 |
| CWE-502 | Deserialization of Untrusted Data | `Deserialization_Cheat_Sheet` | no | yes | 1 | 4 of 6 | yes | 1 | 4 of 5 |
| CWE-352 | Cross-Site Request Forgery | `Cross-Site_Request_Forgery_Prevention_Cheat_Sheet` | no | yes | 1 | 1 of 4 | yes | 1 | 1 of 3 |
| CWE-601 | URL Redirection to Untrusted Site | `Unvalidated_Redirects_and_Forwards_Cheat_Sheet` | no | yes | 1 | 3 of 4 | yes | 1 | 4 of 4 |
| CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine | `Server_Side_Template_Injection_Prevention_Cheat_Sheet` | yes | yes | 1 | 4 of 4 | yes | 1 | 4 of 5 |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | `Mass_Assignment_Cheat_Sheet` | yes | yes | 4 | 1 of 6 | yes | 1 | 3 of 4 |
| CWE-1021 | Improper Restriction of Rendered UI Layers or Frames | `Clickjacking_Defense_Cheat_Sheet` | no | yes | 1 | 3 of 4 | yes | 1 | 2 of 2 |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | `File_Upload_Cheat_Sheet` | yes | yes | 2 | 5 of 6 | yes | 1 | 4 of 4 |
| CWE-943 | Improper Neutralization of Special Elements in Data Query Logic | `NoSQL_Security_Cheat_Sheet` | no | yes | 3 | 1 of 4 | yes | 1 | 1 of 5 |

## Caveats

- The grades are AI-produced and unreviewed: the original set by Hong Yi's AI run, the added set by Claude, done blind.
- There is one grader per label.
- There are only 9 CWEs in part A.
- This measures topic relevance, not whether guidance changes verdicts (that is step 4, item 3).
