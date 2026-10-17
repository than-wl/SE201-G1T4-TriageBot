"""Build the local knowledge base from a downloaded OWASP Cheat Sheet bundle.

Local-only transform: reads the already-downloaded HTML copy of
https://cheatsheetseries.owasp.org (the site's "Download Site" button)
and writes the committed KB of record next to this script:

    docs/<Sheet_Name>.json   one file per cheat sheet: heading-based chunks
    cwe_map.json             CWE id -> [docs]  (mention-based + curated pins)
    common.json              chunks always included regardless of CWE

No network access at any point; fetch happens only when a human updates
the downloaded bundle. Chunking is heading-based: one chunk per section
(h2-h4 path), oversized sections split at block boundaries, tiny
sections dropped. Parent-child chunking / embeddings are a documented
future upgrade if keyword-ranked retrieval proves inadequate.

Usage:
    py -I triagebot/nodes/context/kb/build_kb.py --source <path>/site/cheatsheets
"""

import argparse
import json
import re
from html.parser import HTMLParser
from pathlib import Path

CANONICAL_URL = "https://cheatsheetseries.owasp.org/cheatsheets/{name}"

# Chunks shorter than this (chars) are dropped as noise (e.g. bare
# "References" link lists).
MIN_CHUNK_CHARS = 40
# Sections longer than this are split at block boundaries; a single
# oversized block (one giant code sample) stays intact as its own chunk
# rather than being cut mid-code.
MAX_CHUNK_CHARS = 2000

# Sections always included in the payload regardless of the alert's CWE,
# keyed by sheet; matched by section-path prefix so subsections ride along.
COMMON_SOURCES = {
    "Secure_Code_Review_Cheat_Sheet": [
        "Introduction",
        "Review Methodology",
        "Common Vulnerability Patterns",
        "Review Techniques",
    ],
    "Injection_Prevention_Cheat_Sheet": [
        "Introduction",
        "Injection Prevention Rules",
    ],
    "Input_Validation_Cheat_Sheet": [
        "Introduction",
        "Input Validation Strategies",
    ],
}

# Curated CWE -> docs pins. Mention-based detection alone is not enough:
# the cheat sheets rarely write their own CWE id in prose (e.g. the SQL
# Injection sheet never says "CWE-89"), so these pins guarantee the CWE
# gate hits for the OWASP Benchmark's categories. Merged with (union of)
# the auto-detected mention index at build time.
# Keys follow the OWASP Benchmark Java v1.2 categories; sheets are the
# dedicated prevention sheets for each family.
PINNED_CWE_DOCS: dict[str, list[str]] = {
    "CWE-22": [  # path traversal; no dedicated sheet, best-effort neighbourhood
        "File_Upload_Cheat_Sheet",
        "Injection_Prevention_Cheat_Sheet",
    ],
    "CWE-78": [  # OS command injection
        "OS_Command_Injection_Defense_Cheat_Sheet",
        "Injection_Prevention_Cheat_Sheet",
        "Java_Security_Cheat_Sheet",
    ],
    "CWE-79": [  # cross-site scripting
        "Cross_Site_Scripting_Prevention_Cheat_Sheet",
        "DOM_based_XSS_Prevention_Cheat_Sheet",
        "XSS_Filter_Evasion_Cheat_Sheet",
    ],
    "CWE-89": [  # SQL injection (checkpoint demonstration category)
        "SQL_Injection_Prevention_Cheat_Sheet",
        "Query_Parameterization_Cheat_Sheet",
        "Injection_Prevention_Cheat_Sheet",
        "Java_Security_Cheat_Sheet",
    ],
    "CWE-90": [  # LDAP injection
        "LDAP_Injection_Prevention_Cheat_Sheet",
        "Injection_Prevention_Cheat_Sheet",
    ],
    "CWE-94": [  # code injection
        "Injection_Prevention_Cheat_Sheet",
        "Java_Security_Cheat_Sheet",
    ],
    "CWE-95": [  # eval injection
        "Injection_Prevention_Cheat_Sheet",
        "Java_Security_Cheat_Sheet",
    ],
    "CWE-611": [  # XML external entity (XXE)
        "XML_External_Entity_Prevention_Cheat_Sheet",
        "XML_Security_Cheat_Sheet",
    ],
    "CWE-918": [  # server-side request forgery
        "Server_Side_Request_Forgery_Prevention_Cheat_Sheet",
    ],
}

_CWE_RE = re.compile(r"CWE[-_ ]?(\d{2,4})", re.IGNORECASE)

_SKIP_TAGS = {"script", "style", "nav", "footer"}
_BLOCK_END_TAGS = {"p", "li", "td", "th", "blockquote"}
_HEADING_TAGS = {"h1": 1, "h2": 2, "h3": 3, "h4": 4}


class SheetParser(HTMLParser):
    """Extract ordered (section-path, text-blocks) from one mkdocs sheet.

    Only content inside <article> is considered. Headings h1-h4 (all
    carry id anchors in this bundle) open sections; the h1 is the sheet
    title and stays out of the section path. "headerlink" permalink
    anchors (the ¶ glyphs) and nav/footer/script/style are skipped.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.sections: list[tuple[str, list[str]]] = []  # (path, blocks)
        self._in_article = False
        self._skip_depth = 0        # inside script/style/nav/footer
        self._link_skip = 0         # inside a.headerlink anchors
        self._heading_level = 0     # >0 while inside an h1-h4
        self._heading_buf: list[str] = []
        self._stack: list[tuple[int, str]] = []  # open headings (level, title)
        self._blocks: list[str] = []  # finished blocks of current section
        self._buf: list[str] = []     # current p/li/... buffer
        self._in_pre = False
        self._pre_buf: list[str] = []

    # --- section assembly -------------------------------------------------

    def _section_path(self) -> str:
        return " > ".join(title for _, title in self._stack)

    def _finish_section(self) -> None:
        if self._blocks:
            self.sections.append((self._section_path(), self._blocks))
        self._blocks = []

    def _open_heading(self, level: int, raw_title: str) -> None:
        self._finish_section()
        title = " ".join(raw_title.split())
        while self._stack and self._stack[-1][0] >= level:
            self._stack.pop()
        if level == 1:
            if not self.title:
                self.title = title
        else:
            self._stack.append((level, title))

    # --- block buffers ----------------------------------------------------

    def _flush_text(self) -> None:
        text = " ".join("".join(self._buf).split())
        self._buf = []
        if text:
            self._blocks.append(text)

    def _flush_pre(self) -> None:
        code = "".join(self._pre_buf).strip("\n")
        self._pre_buf = []
        self._in_pre = False
        if code.strip():
            fence = "```"
            while fence in code:  # never break the fence
                fence += "`"
            self._blocks.append(f"{fence}\n{code}\n{fence}")

    # --- HTMLParser hooks -------------------------------------------------

    def handle_starttag(self, tag, attrs) -> None:
        if tag == "article":
            self._in_article = True
            return
        if not self._in_article:
            return
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        classes = dict(attrs).get("class", "").split()
        if tag == "a" and "headerlink" in classes:
            self._link_skip += 1
            return
        if self._link_skip:
            return
        if tag in _HEADING_TAGS:
            self._heading_level = _HEADING_TAGS[tag]
            self._heading_buf = []
            return
        if self._in_pre:
            if tag == "br":
                self._pre_buf.append("\n")
            return
        if tag == "pre":
            self._flush_text()
            self._in_pre = True
            self._pre_buf = []
            return
        if tag in _BLOCK_END_TAGS:
            self._flush_text()
            return
        if tag == "br":
            self._buf.append(" ")

    def handle_endtag(self, tag) -> None:
        if tag == "article":
            self._finish_section()
            self._in_article = False
            return
        if not self._in_article:
            return
        if tag in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth:
            return
        if tag == "a" and self._link_skip:
            self._link_skip -= 1
            return
        if self._link_skip:
            return
        if tag in _HEADING_TAGS and self._heading_level == _HEADING_TAGS[tag]:
            self._open_heading(self._heading_level, "".join(self._heading_buf))
            self._heading_buf = []
            self._heading_level = 0
            return
        if tag == "pre" and self._in_pre:
            self._flush_pre()
            return
        if tag in _BLOCK_END_TAGS:
            self._flush_text()

    def handle_data(self, data) -> None:
        if not self._in_article or self._skip_depth or self._link_skip:
            return
        if self._heading_level:
            self._heading_buf.append(data)
        elif self._in_pre:
            self._pre_buf.append(data)
        else:
            self._buf.append(data)


def _split_long(blocks: list[str], limit: int) -> list[list[str]]:
    """Split a section's blocks into parts of at most ~limit chars.

    Splits only between blocks (never mid-paragraph or mid-code); a
    single block longer than the limit becomes its own oversized part.
    """
    parts: list[list[str]] = []
    current: list[str] = []
    current_len = 0
    for block in blocks:
        if current and current_len + len(block) + 2 > limit:
            parts.append(current)
            current, current_len = [], 0
        current.append(block)
        current_len += len(block) + 2
    if current:
        parts.append(current)
    return parts


def build(source: Path, out: Path) -> None:
    html_files = sorted(source.glob("*.html"))
    if not html_files:
        raise SystemExit(f"no .html files found under {source}")

    out_docs = out / "docs"
    out_docs.mkdir(parents=True, exist_ok=True)

    cwe_index: dict[str, set[str]] = {}
    common_chunks: list[dict] = []
    total_chunks = 0
    warnings = 0

    for html_path in html_files:
        parser = SheetParser()
        parser.feed(html_path.read_text(encoding="utf-8", errors="replace"))
        parser.close()

        doc = html_path.stem
        url = CANONICAL_URL.format(name=html_path.name)
        chunks: list[dict] = []
        idx = 0
        for section, blocks in parser.sections:
            for part in _split_long(blocks, MAX_CHUNK_CHARS):
                text = "\n\n".join(part)
                if len(text) < MIN_CHUNK_CHARS:
                    continue
                idx += 1
                chunk = {
                    "chunk_id": f"{doc}#{idx:03d}",
                    "doc": doc,
                    "section": section or parser.title,
                    "url": url,
                    "text": text,
                }
                chunks.append(chunk)
                for num in _CWE_RE.findall(f"{section} {text}"):
                    cwe_index.setdefault(f"CWE-{num}", set()).add(doc)

        if not chunks:
            warnings += 1
            print(f"  WARNING: {html_path.name}: no chunkable <article> content")
            continue

        record = {"doc": doc, "title": parser.title or doc, "url": url, "chunks": chunks}
        (out_docs / f"{doc}.json").write_text(
            json.dumps(record, indent=1, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        total_chunks += len(chunks)
        print(f"  {doc}: {len(chunks)} chunks")

        prefixes = COMMON_SOURCES.get(doc)
        if prefixes:
            for chunk in chunks:
                sec = chunk["section"]
                if any(sec == p or sec.startswith(p + " >") for p in prefixes):
                    common_chunks.append(chunk)

    # Merge curated pins (union) into the mention-based index; a pinned
    # doc name that matches no input file is a typo and must fail loudly.
    input_names = {p.stem for p in html_files}
    for cwe_id, docs in PINNED_CWE_DOCS.items():
        for doc in docs:
            if doc not in input_names:
                raise SystemExit(
                    f"PINNED_CWE_DOCS typo: {cwe_id} pins unknown sheet {doc!r}"
                )
        cwe_index.setdefault(cwe_id, set()).update(docs)

    cwe_map = {key: sorted(docs) for key, docs in sorted(cwe_index.items())}
    (out / "cwe_map.json").write_text(
        json.dumps(cwe_map, indent=1) + "\n", encoding="utf-8"
    )
    (out / "common.json").write_text(
        json.dumps({"chunks": common_chunks}, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print()
    print(f"docs written : {len(html_files) - warnings} -> {out_docs}")
    print(f"chunks total : {total_chunks}")
    print(f"cwe_map keys : {len(cwe_map)}")
    print(f"common chunks: {len(common_chunks)}")
    if warnings:
        print(f"warnings     : {warnings} sheet(s) produced no chunks")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Build the local OWASP cheat-sheet KB (offline, stdlib only)."
    )
    ap.add_argument(
        "--source",
        type=Path,
        required=True,
        help="directory of downloaded cheatsheet .html files",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="KB output directory (default: this script's own directory)",
    )
    args = ap.parse_args()
    build(args.source.resolve(), args.out.resolve())


if __name__ == "__main__":
    main()
