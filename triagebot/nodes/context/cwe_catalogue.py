"""Official MITRE CWE catalogue: fetch once, verify the hash, look up CWE text.

The lookup is deterministic: a CWE ID from the scanner maps to one MITRE
record. Deprecated records are left out, so a deprecated ID is a miss and
the validator routes that alert to human review. Nothing here calls a model.

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


def load_entries(xml_path: Path) -> dict[str, dict]:
    """Parse the catalogue into {"CWE-89": {"name", "description"}}, skipping deprecated records."""
    root = ET.parse(xml_path).getroot()
    entries: dict[str, dict] = {}
    for element in root.iter():
        if _local(element.tag) != "Weakness" or element.get("Status") == "Deprecated":
            continue
        description = next((c for c in element if _local(c.tag) == "Description"), None)
        text = " ".join("".join(description.itertext()).split()) if description is not None else ""
        entries[f"CWE-{element.get('ID')}"] = {"name": element.get("Name", ""), "description": text}
    return entries


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
    def query_text(entry: dict) -> str:
        """The text used as the retrieval query: the MITRE name, then its description."""
        return f"{entry['name']}. {entry['description']}"


if __name__ == "__main__":
    installed = install()
    print(f"Installed {installed} (SHA-256 verified)")
    sys.exit(0)
