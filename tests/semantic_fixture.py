"""A tiny offline knowledge base, MITRE catalogue and fake embedder for the semantic set-up tests.

The knowledge base has one sheet per case the set-up rules handle: general
sheets, one with an oversized chunk, a retired sheet, an attack catalogue, and
sheets tagged python and java in its own scope.json.
"""
import json
from pathlib import Path

import numpy as np

CATALOGUE = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" xmlns:xhtml="http://www.w3.org/1999/xhtml"><Weaknesses>
  <Weakness ID="89" Name="SQL Injection" Status="Stable">
    <Description>Input reaches an SQL command without neutralisation.</Description>
    <Extended_Description>
      <xhtml:p>Without sufficient removal or quoting of SQL syntax, the input is read as <xhtml:b>SQL</xhtml:b> rather than data.</xhtml:p>
      <xhtml:p>This can be used to alter query logic.</xhtml:p>
    </Extended_Description>
    <Alternate_Terms>
      <Alternate_Term><Term>SQLi</Term><Description>Short form.</Description></Alternate_Term>
      <Alternate_Term><Term>SQL injection</Term></Alternate_Term>
    </Alternate_Terms>
    <Potential_Mitigations>
      <Mitigation Mitigation_ID="MIT-1">
        <Phase>Architecture and Design</Phase>
        <Strategy>Libraries or Frameworks</Strategy>
        <Description>Use a vetted library that prevents this weakness.</Description>
      </Mitigation>
      <Mitigation>
        <Phase>Implementation</Phase>
        <Phase>Operation</Phase>
        <Description><xhtml:p>Use prepared statements.</xhtml:p><xhtml:ul><xhtml:li>Bind every parameter.</xhtml:li><xhtml:li>Never concatenate.</xhtml:li></xhtml:ul></Description>
      </Mitigation>
    </Potential_Mitigations>
    <Demonstrative_Examples><Demonstrative_Example><Intro_Text>EXAMPLE-TEXT-NOT-GUIDANCE</Intro_Text></Demonstrative_Example></Demonstrative_Examples>
    <Observed_Examples><Observed_Example><Reference>CVE-0000-0000</Reference></Observed_Example></Observed_Examples>
  </Weakness>
  <Weakness ID="916" Name="Hashing Too Weakly" Status="Draft">
    <Description>Password hash is computed with a weak hash function.</Description>
  </Weakness>
  <Weakness ID="1" Name="Old Entry" Status="Deprecated">
    <Description>Retired.</Description>
  </Weakness>
</Weaknesses></Weakness_Catalog>
"""

# One paragraph of 6 sentences (about 300 characters), repeated: about 2,450 characters.
_PARAGRAPH = " ".join(f"Bind SQL parameter {n} through the driver." for n in range(1, 8))
BIG_TEXT = "\n\n".join([_PARAGRAPH] * 8)


def _chunk(doc, number, text, section="S"):
    return {"chunk_id": f"{doc}#{number:03d}", "doc": doc, "section": section,
            "text": text, "url": f"https://example.test/{doc}"}


DOCS = {
    "SQL_Sheet": [_chunk("SQL_Sheet", 1, "Use parameterised SQL queries.", "SQL"),
                  _chunk("SQL_Sheet", 2, "Never concatenate input into an SQL statement.", "SQL")],
    "Hash_Sheet": [_chunk("Hash_Sheet", 1, "Use a slow hash such as bcrypt for password hash storage.",
                          "Hashing")],
    "Big_Sheet": [_chunk("Big_Sheet", 1, BIG_TEXT, "Binding")],
    "Old_Sheet": [_chunk("Old_Sheet", 1, "DEPRECATED: see the SQL sheet. SQL SQL.", "Old")],
    "Evasion_Sheet": [_chunk("Evasion_Sheet", 1, "SQL payloads: ' OR 1=1 -- SQL SQL", "Payloads")],
    "Django_Sheet": [_chunk("Django_Sheet", 1, "In Django, pass SQL params to raw(); sql.", "ORM")],
    "Java_Sheet": [_chunk("Java_Sheet", 1, "In Java, use PreparedStatement for SQL.", "JDBC")],
}
COMMON = [_chunk("common", 1, "Validate all input.", "General")]
SCOPE = {
    "excluded": {
        "Old_Sheet": {"rule": "retired", "reason": "Title starts with DEPRECATED:."},
        "Evasion_Sheet": {"rule": "attack_catalogue", "reason": "A list of attack strings."},
    },
    "platform": {
        "Django_Sheet": {"platform": "python", "reason": "Django is a Python framework."},
        "Java_Sheet": {"platform": "java", "reason": "Java only."},
    },
    "general": ["Big_Sheet", "Hash_Sheet", "SQL_Sheet"],
}


def write_kb(kb_dir: Path, scope=True) -> Path:
    (kb_dir / "docs").mkdir(parents=True)
    (kb_dir / "cwe_map.json").write_text("{}", encoding="utf-8")
    (kb_dir / "common.json").write_text(json.dumps({"chunks": COMMON}), encoding="utf-8")
    for doc, chunks in DOCS.items():
        (kb_dir / "docs" / f"{doc}.json").write_text(
            json.dumps({"doc": doc, "title": doc, "chunks": chunks}), encoding="utf-8")
    if scope:
        (kb_dir / "scope.json").write_text(json.dumps(SCOPE), encoding="utf-8")
    return kb_dir


def _unit(values):
    vector = np.array(values, dtype=np.float32)
    return vector / np.linalg.norm(vector)


class KeywordEmbedder:
    """Two dimensions: how often "sql" and "hash" occur. Records the queries it was asked."""

    def __init__(self):
        self.queries = []
        self.embedded = []

    @staticmethod
    def _vector(text):
        lowered = text.lower()
        return _unit([lowered.count("sql"), lowered.count("hash"), 0.01])

    def embed_documents(self, texts):
        self.embedded.extend(texts)
        return np.array([self._vector(t) for t in texts], dtype=np.float32)

    def embed_query(self, text):
        self.queries.append(text)
        return self._vector(text)


def alert(cwe):
    return {"case_id": "C1", "file": "Demo.java", "rule_id": "r", "cwe": cwe,
            "start_line": 2, "end_line": 2, "message": "m"}
