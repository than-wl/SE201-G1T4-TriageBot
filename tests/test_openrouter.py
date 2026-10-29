"""Offline contract tests for the paid OpenRouter boundary."""

from io import BytesIO
import json
import os
from unittest.mock import patch
import unittest

from triagebot.llm.openrouter import OpenRouterCaller


class StructuredOutput(unittest.TestCase):
    def test_request_requires_strict_supported_json(self):
        captured = {}
        response = {"model": "fixture", "choices": [{"message": {"content": json.dumps({
            "verdict": "human_review", "explanation": "Missing context",
            "citations": [], "guidance": [],
        })}, "finish_reason": "stop"}], "usage": {}}

        def fake_urlopen(request, timeout):
            captured["payload"] = json.loads(request.data)
            return BytesIO(json.dumps(response).encode("utf-8"))

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test"}), \
                patch("triagebot.llm.openrouter.urlopen", fake_urlopen):
            result = OpenRouterCaller().complete({
                "system": "system", "user": "user", "max_tokens": 100,
            })

        self.assertEqual(result["verdict"], "human_review")
        self.assertTrue(captured["payload"]["provider"]["require_parameters"])
        response_format = captured["payload"]["response_format"]
        self.assertEqual(response_format["type"], "json_schema")
        self.assertTrue(response_format["json_schema"]["strict"])
        self.assertEqual(
            set(response_format["json_schema"]["schema"]["required"]),
            {"verdict", "analysis", "explanation", "citations", "guidance"})


if __name__ == "__main__":
    unittest.main()
