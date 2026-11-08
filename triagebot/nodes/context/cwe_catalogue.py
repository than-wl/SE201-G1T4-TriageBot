"""Official MITRE CWE catalogue: fetch once, verify the hash, look up CWE text.

The lookup is deterministic: a CWE ID from the scanner maps to one MITRE
record. Deprecated records are left out, so a deprecated ID is a miss and
the validator routes that alert to human review. Nothing here calls a model.

Text quoted from the catalogue is MITRE's; its copyright line and terms of use
are reproduced in MITRE_CWE_NOTICE.md next to this file.

Install (network needed once; the zip is pinned by SHA-256 in config):
    python -m triagebot.nodes.context.cwe_catalogue
"""

import hashlib
import io
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from triagebot import config

_CWE_ID = re.compile(r"(\d+)")


def _local(tag: str) -> str:
    """Element name without its XML namespace ("{ns}Weakness" -> "Weakness")."""
    return tag.split("}")[-1]


def cwe_key(value: str) -> str:
    """"89" / "CWE-89" / "CWE-89: Improper ..." -> "CWE-89"; anything else -> ""."""
    match = _CWE_ID.search(value or "")
    return f"CWE-{int(match.group(1))}" if match else ""


def install(url: str = config.CWE_CATALOGUE_URL,
            sha256: str = config.CWE_CATALOGUE_SHA256,
            out_dir: Path = config.CWE_CATALOGUE_DIR) -> Path:
    """Download the catalogue zip, check its SHA-256, extract the XML and return its path."""
    if not sha256:
        raise ValueError("CWE_CATALOGUE_SHA256 is not pinned; refusing to install an unverified catalogue")
    with urllib.request.urlopen(url, timeout=120) as response:
        raw = response.read()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != sha256:
        raise ValueError(f"CWE catalogue hash mismatch: expected {sha256}, got {actual}")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = [name for name in archive.namelist() if name.endswith(".xml")]
        if len(members) != 1:
            raise ValueError(f"expected exactly one XML file in the catalogue zip, found {members}")
        xml_bytes = archive.read(members[0])
    target = out_dir / members[0]
    target.write_bytes(xml_bytes)
    return target


_BLOCKS = frozenset({"p", "div", "pre", "blockquote", "table", "tr", "br"})
_LISTS = frozenset({"ul", "ol"})


def _flat(element) -> str:
    """All text inside an element, whitespace collapsed to single spaces."""
    return " ".join("".join(element.itertext()).split())


def _paragraphs(element) -> list[str]:
    """MITRE structured text (XHTML p / div / ul ...) as plain paragraphs, list items as "- item"."""
    paragraphs: list[str] = []
    pending: list[str] = [element.text or ""]

    def flush() -> None:
        text = " ".join("".join(pending).split())
        pending.clear()
        if text:
            paragraphs.append(text)

    for child in element:
        tag = _local(child.tag)
        if tag in _LISTS:
            flush()
            paragraphs.extend(f"- {text}" for text in (_flat(item) for item in child) if text)
        elif tag in _BLOCKS:
            flush()
            paragraphs.extend(_paragraphs(child))
        else:                                   # inline (b, i, code, a ...): part of the paragraph
            pending.append("".join(child.itertext()))
        pending.append(child.tail or "")
    flush()
    return paragraphs


def _child(element, name):
    return next((c for c in element if _local(c.tag) == name), None)


def _children(element, name):
    return [c for c in element if _local(c.tag) == name] if element is not None else []


def load_entries(xml_path: Path) -> dict[str, dict]:
    """Parse the catalogue into {"CWE-89": {...}}, skipping deprecated records.

    Each entry holds "id", "name" and "description" (the decision 21 query text),
    plus "alternate_terms" (the Term text of each Alternate_Term),
    "extended_description" (paragraphs) and "mitigations" ({"phases", "text"} per
    Potential_Mitigations/Mitigation). Demonstrative and observed examples are not read.
    """
    root = ET.parse(xml_path).getroot()
    entries: dict[str, dict] = {}
    for element in root.iter():
        if _local(element.tag) != "Weakness" or element.get("Status") == "Deprecated":
            continue
        description = _child(element, "Description")
        extended = _child(element, "Extended_Description")
        terms = [_flat(term) for alt in _children(_child(element, "Alternate_Terms"), "Alternate_Term")
                 for term in _children(alt, "Term")]
        mitigations = []
        for mitigation in _children(_child(element, "Potential_Mitigations"), "Mitigation"):
            text = _child(mitigation, "Description")
            paragraphs = _paragraphs(text) if text is not None else []
            if paragraphs:
                mitigations.append({"phases": [_flat(p) for p in _children(mitigation, "Phase")],
                                    "text": " ".join(paragraphs)})
        entries[f"CWE-{element.get('ID')}"] = {
            "id": element.get("ID"),
            "name": element.get("Name", ""),
            "description": _flat(description) if description is not None else "",
            "alternate_terms": [t for t in terms if t],
            "extended_description": _paragraphs(extended) if extended is not None else [],
            "mitigations": mitigations,
        }
    return entries


_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
MITIGATIONS_HEADING = "Potential mitigations:"


def _within(paragraph: str, room: int) -> str:
    """The longest run of whole sentences from the start of ``paragraph`` that fits ``room``."""
    kept = ""
    for sentence in _SENTENCE_END.split(paragraph):
        candidate = f"{kept} {sentence}" if kept else sentence
        if len(candidate) > room:
            break
        kept = candidate
    return kept


def trim_paragraphs(paragraphs: list[str], max_chars: int) -> str:
    """Join paragraphs with blank lines, cut at a paragraph, then sentence, boundary to fit.

    Only when not even the first sentence fits is the text cut at the last space
    within the cap (and, with no space at all, at the cap itself).
    """
    text = ""
    for paragraph in paragraphs:
        candidate = f"{text}\n\n{paragraph}" if text else paragraph
        if len(candidate) <= max_chars:
            text = candidate
            continue
        part = _within(paragraph, max_chars - (len(text) + 2 if text else 0))
        if part:
            text = f"{text}\n\n{part}" if text else part
        break
    if text.endswith(MITIGATIONS_HEADING):            # a heading with nothing under it
        text = text[: -len(MITIGATIONS_HEADING)].rstrip()
    if not text and paragraphs:
        head = paragraphs[0][:max_chars]
        text = head.rsplit(" ", 1)[0] if " " in head and len(paragraphs[0]) > max_chars else head
    return text


class CweCatalogue:
    """Read-only view over an installed catalogue file."""

    def __init__(self, xml_path: Path | None = None) -> None:
        self.path = Path(xml_path or config.CWE_CATALOGUE_XML)
        if not self.path.is_file():
            raise FileNotFoundError(
                f"CWE catalogue not found at {self.path}; run "
                "`python -m triagebot.nodes.context.cwe_catalogue` once to install it"
            )
        self._entries = load_entries(self.path)

    def lookup(self, cwe: str) -> dict | None:
        """MITRE name and description for a CWE ID, or None when it is unknown or deprecated."""
        return self._entries.get(cwe_key(cwe))

    @staticmethod
    def query_text(entry: dict, *, alternate_terms: bool = False) -> str:
        """The text used as the retrieval query: the MITRE name, then its description.

        With ``alternate_terms`` (rule R1) the names people actually use come
        between them: "{Name}. Also known as: {t1}, {t2}. {Description}". With no
        alternate terms the query is the same as without the rule.
        """
        terms = entry.get("alternate_terms", []) if alternate_terms else []
        also = f" Also known as: {', '.join(terms)}." if terms else ""
        return f"{entry['name']}.{also} {entry['description']}"

    @staticmethod
    def guidance_chunk(entry: dict, max_chars: int) -> dict:
        """The MITRE record as one guidance chunk (rule R2): attached by CWE ID, never searched.

        Text: Description, then Extended_Description, then Potential_Mitigations
        (each prefixed with its phase), trimmed at a paragraph or sentence boundary
        to ``max_chars``. Demonstrative and observed examples are left out.
        """
        paragraphs = [entry["description"], *entry.get("extended_description", [])]
        mitigations = entry.get("mitigations", [])
        if mitigations:
            paragraphs.append(MITIGATIONS_HEADING)
            for mitigation in mitigations:
                phase = " / ".join(mitigation["phases"])
                paragraphs.append(f"- {phase}: {mitigation['text']}" if phase
                                  else f"- {mitigation['text']}")
        cwe_id = entry["id"]
        return {
            "chunk_id": f"MITRE-CWE-{cwe_id}",
            "doc": "MITRE_CWE",
            "section": f"CWE-{cwe_id}: {entry['name']}",
            "text": trim_paragraphs([p for p in paragraphs if p], max_chars),
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
        }


if __name__ == "__main__":
    installed = install()
    print(f"Installed {installed} (SHA-256 verified)")
    sys.exit(0)
