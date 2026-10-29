"""Bounded Java relationship retrieval behind the context-payload seam."""

from pathlib import Path
import re

from triagebot import config


_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
_FQ_CLASS = re.compile(r"\b((?:[a-z_][\w$]*\.)+([A-Z][\w$]*))\s*\.")
_CLASS_NAME = re.compile(r"\b([A-Z][\w$]*)\b")
_NOT_METHODS = {"if", "for", "while", "switch", "catch", "new", "return", "throw"}
_INFRASTRUCTURE_SUFFIXES = ("Helper", "Util", "Utils")


def _brace_delta(line):
    delta = 0
    quote = None
    escaped = False
    for char in line:
        if escaped:
            escaped = False
        elif quote and char == "\\":
            escaped = True
        elif quote and char == quote:
            quote = None
        elif quote is None and char in "\"'":
            quote = char
        elif quote is None and char == "{":
            delta += 1
        elif quote is None and char == "}":
            delta -= 1
    return delta


def _method_spans(lines):
    spans = {}
    for start in range(len(lines)):
        header = ""
        for end in range(start, min(start + 5, len(lines))):
            header += " " + lines[end].strip()
            if ";" in header and ("{" not in header or header.index(";") < header.index("{")):
                break
            if "{" not in header:
                continue
            before = header.split("{", 1)[0]
            names = _CALL.findall(before)
            if not names or names[-1] in _NOT_METHODS or " class " in f" {before} ":
                break
            name = names[-1]
            depth = 0
            finish = end
            for finish in range(end, len(lines)):
                depth += _brace_delta(lines[finish])
                if depth == 0:
                    break
            spans.setdefault(name, (start + 1, finish + 1))
            break
    return spans


def _numbered(lines, numbers):
    return [f"{number}: {lines[number - 1]}" for number in sorted(numbers)]


def _java_path(root, qualified_name):
    return root / "src" / "main" / "java" / Path(*qualified_name.split(".")).with_suffix(".java")


def _is_context_candidate(qualified_name):
    return not qualified_name.rsplit(".", 1)[-1].endswith(_INFRASTRUCTURE_SUFFIXES)


def _clean_lines(path):
    from triagebot.nodes.context.payload import strip_comments

    return strip_comments(path.read_text(encoding="utf-8", errors="replace")).splitlines()


def build_source_context(root, alert, clean_lines):
    """Return the alert window plus directly related same-file and helper code."""
    start = max(1, alert["start_line"] - config.SOURCE_WINDOW_LINES)
    end = min(len(clean_lines), alert["end_line"] + config.SOURCE_WINDOW_LINES)
    selected = set(range(start, end + 1))

    calls = set(_CALL.findall("\n".join(clean_lines[number - 1] for number in selected)))
    for name, (method_start, method_end) in _method_spans(clean_lines).items():
        if name in calls:
            selected.update(range(method_start, method_end + 1))

    primary_file = alert["file"]
    full_text = "\n".join(clean_lines)
    queue = [(name, "direct class reference") for name, _ in _FQ_CLASS.findall(full_text)
             if _is_context_candidate(name)]
    related, seen = [], {str((root / primary_file).resolve())}
    line_budget = config.SOURCE_RELATED_MAX_LINES
    while queue and len(related) < config.SOURCE_RELATED_MAX_FILES and line_budget > 0:
        qualified_name, relationship = queue.pop(0)
        path = _java_path(root, qualified_name).resolve()
        if str(path) in seen or not path.is_relative_to(root) or not path.is_file():
            continue
        seen.add(str(path))
        lines = _clean_lines(path)
        numbers = [number for number, line in enumerate(lines, 1) if line.strip()]
        numbers = numbers[:min(line_budget, config.SOURCE_RELATED_MAX_LINES_PER_FILE)]
        line_budget -= len(numbers)
        relative = path.relative_to(root).as_posix()
        related.append({"file": relative, "relationship": relationship,
                        "lines": _numbered(lines, numbers)})

        text = "\n".join(lines)
        discovered = [(name, f"referenced by {relative}")
                      for name, _ in _FQ_CLASS.findall(text) if _is_context_candidate(name)]
        for class_name in _CLASS_NAME.findall(text):
            sibling = path.with_name(class_name + ".java")
            if sibling.is_file():
                package_root = root / "src" / "main" / "java"
                qualified = ".".join(sibling.relative_to(package_root).with_suffix("").parts)
                discovered.append((qualified, f"referenced by {relative}"))
        queue[0:0] = discovered

    return {"file": primary_file, "lines": _numbered(clean_lines, selected),
            "related": related}
