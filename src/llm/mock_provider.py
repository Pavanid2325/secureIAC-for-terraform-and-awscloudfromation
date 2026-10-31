"""Explicit demo provider; empty output is never presented as a security scan."""
import json
import re
from src.llm.base import ProviderResult


class MockProvider:
    model_id = "mock-v2"

    def generate(self, system_prompt, user_prompt):
        context = json.loads(re.search(r"<ANALYSIS_IDENTITY>\n(.*?)\n</ANALYSIS_IDENTITY>", user_prompt, re.S).group(1))
        return ProviderResult(json.dumps({**context, "schema_version": "2", "findings": [],
                                         "summary": "Demo response; no contextual detection performed."}),
                              "mock", self.model_id)
