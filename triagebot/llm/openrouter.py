"""Live caller - OpenRouter chat completions.

API key is read from the environment or the local .env only; model slug
comes from configuration; no automatic retry after a timeout or
billing-uncertain failure (decision 11): every failure returns
{"_error": reason} so roles degrade to a safe human_review report.

The parsed model answer is returned per the base contract; raw usage
(model, tokens, cost, latency) is kept on `last_call` for run recording.
"""

import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_API = "https://openrouter.ai/api/v1/chat/completions"
_DEFAULT_MODEL = "google/gemini-3.8-flash"   # proposal model (decision 6)
_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": [
            "true_positive", "false_positive", "human_review"]},
        "explanation": {"type": "string"},
        "citations": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "file": {"type": "string"}, "line": {"type": "integer"},
                "quote": {"type": "string"},
            },
            "required": ["file", "line", "quote"],
            "additionalProperties": False,
        }},
        "guidance": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "chunk_id": {"type": "string"}, "doc": {"type": "string"},
                "section": {"type": "string"}, "url": {"type": "string"},
            },
            "required": ["chunk_id", "doc", "section", "url"],
            "additionalProperties": False,
        }},
    },
    "required": ["verdict", "explanation", "citations", "guidance"],
    "additionalProperties": False,
}


class OpenRouterCaller:
    def __init__(self, model: str | None = None, timeout: int = 90):
        self.model = model or os.environ.get("OPENROUTER_MODEL") or _DEFAULT_MODEL
        self.timeout = timeout
        self.last_call: dict | None = None   # usage/latency of the latest call
        key = _api_key()
        if not key:
            raise ValueError("OPENROUTER_API_KEY not set (env or repo-root .env)")
        self._key = key

    def complete(self, request: dict) -> dict:
        payload = {
            "model": self.model,
            "max_tokens": request.get("max_tokens", 700),
            "temperature": request.get("temperature", 0.0),
            # minimal, hidden reasoning: keeps recorded runs cheap and clean
            "reasoning": {"effort": "minimal", "exclude": True},
            "provider": {"require_parameters": True},
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "triage", "strict": True, "schema": _REPORT_SCHEMA}},
            "messages": [
                {"role": "system", "content": request["system"]},
                {"role": "user", "content": request["user"]},
            ],
        }
        http = Request(
            _API,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": "Bearer " + self._key,
                     "Content-Type": "application/json"},
        )
        started = time.perf_counter()
        try:
            with urlopen(http, timeout=self.timeout) as response:
                raw = json.load(response)
        except HTTPError as exc:            # includes billing/auth failures
            return {"_error": f"HTTP {exc.code}: {exc.reason}"}
        except (URLError, TimeoutError, OSError) as exc:
            return {"_error": f"{type(exc).__name__}: {exc}"}
        latency = time.perf_counter() - started

        try:
            content = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            return {"_error": f"unexpected response shape: {exc}"}
        self.last_call = {
            "model": raw.get("model", self.model),
            "provider": raw.get("provider"),
            "usage": raw.get("usage", {}),
            "latency_seconds": round(latency, 3),
            "finish_reason": raw["choices"][0].get("finish_reason"),
            "raw_content": content,
        }
        return _parse_json(content)


def _api_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if key:
        return key
    env_file = Path(__file__).resolve().parents[2] / ".env"
    if env_file.exists():                  # local only, never committed
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition("=")
            if name.strip() == "OPENROUTER_API_KEY":
                return value.strip()
    return ""


def _parse_json(content: str) -> dict:
    """Parse the model answer; tolerate markdown fences, nothing more."""
    text = (content or "").strip()
    for attempt in (text,
                    text.removeprefix("```json").removesuffix("```").strip(),
                    text.removeprefix("```").removesuffix("```").strip()):
        try:
            value = json.loads(attempt)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue
    return {"_error": "unparseable model answer (not a JSON object)"}
