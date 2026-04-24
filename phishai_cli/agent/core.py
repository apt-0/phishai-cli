"""PhishAI Agent — LLM-powered tool orchestrator.

The agent receives user input (email file, URL, or natural language),
decides which engine tools to call and in what order, then produces
a final verdict in natural language.

Supports:
  - Ollama (native /api/chat with tool-calling)
  - OpenAI, OpenRouter, LM Studio (OpenAI-compatible /v1/chat/completions)
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
import urllib.error

from phishai_cli.agent.tools import TOOL_DEFINITIONS, execute_tool

logger = logging.getLogger("phishai.agent")

SYSTEM_PROMPT = """\
You are PhishAI Agent, an expert cybersecurity analyst specializing in phishing detection.

You have access to these tools:
- parse_email: Parse an email file into structured fields
- quick_scan: Fast local-only scan (red flags, NLP, risk score)
- deep_analyze: Full analysis with enrichment (WHOIS, DNS) and LLM
- analyze_url: Analyze a URL (headless browser, screenshots, brand detection)
- verify_sender: Verify sender domain (WHOIS age, DNS, BIMI)

When given an email file (.eml):
1. Start with quick_scan to get an overview
2. If risk is medium/high or you find suspicious URLs, investigate further
3. Use analyze_url on suspicious URLs found in the email
4. Use verify_sender on the sender domain if authentication looks weak
5. Use deep_analyze only if needed (enrichment takes longer)

When given a URL:
1. Use analyze_url to check for phishing indicators

When given a domain or email address:
1. Use verify_sender to check legitimacy

After gathering all evidence, provide a clear verdict:
- Is this phishing, suspicious, or legitimate?
- What are the key indicators?
- What should the user do?

Be concise and actionable. Use bullet points for indicators.
"""

# Ollama native tool format (different from OpenAI)
OLLAMA_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": t["function"]["name"],
            "description": t["function"]["description"],
            "parameters": t["function"]["parameters"],
        },
    }
    for t in TOOL_DEFINITIONS
]

MAX_TOOL_ROUNDS = 8
TIMEOUT_SECONDS = 300  # 5 minutes for local models


class Agent:
    """LLM-powered agent that orchestrates phishai-engine tools."""

    def __init__(
        self,
        provider_type: str = "ollama",
        model: str = "",
        base_url: str = "",
        api_key: str = "",
    ):
        from phishai.llm.provider import PROVIDER_PRESETS

        preset = PROVIDER_PRESETS.get(provider_type, PROVIDER_PRESETS.get("ollama", {}))
        self.provider_type = provider_type
        self.base_url = base_url or preset.get("base_url", "")
        self.api_key = api_key
        self.model = model or preset.get("default_model", "")
        self.is_ollama = provider_type == "ollama" or (
            any(h in self.base_url for h in ("localhost", "127.0.0.1"))
            and "/v1" in self.base_url
        )
        self.messages: list[dict] = []

    def run(self, user_input: str) -> str:
        """Process user input through the agent loop."""
        enriched = self._enrich_input(user_input)

        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": enriched},
        ]

        for _round in range(MAX_TOOL_ROUNDS):
            response = self._call_llm()
            if response is None:
                return "Error: could not get a response from the LLM."

            tool_calls = response.get("tool_calls") or []
            content = (response.get("content") or "").strip()

            # Strip thinking tags from content
            if content and "</think>" in content:
                after = content.split("</think>")[-1].strip()
                if after:
                    content = after

            if not tool_calls:
                return content if content else "Analysis complete — no further findings."

            # Append assistant message with tool calls
            self.messages.append(response)

            # Execute each tool call
            for tc in tool_calls:
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                raw_args = fn.get("arguments", "{}")

                # Arguments can be a string (JSON) or already a dict
                if isinstance(raw_args, str):
                    try:
                        tool_args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        tool_args = {}
                else:
                    tool_args = raw_args

                logger.info("Agent calling tool: %s(%s)", tool_name, tool_args)

                result_str = execute_tool(tool_name, tool_args)

                # Truncate very large results
                if len(result_str) > 8000:
                    result_str = result_str[:8000] + "\n... (truncated)"

                self.messages.append({
                    "role": "tool",
                    "content": result_str,
                })

        # Exhausted rounds
        self.messages.append({
            "role": "user",
            "content": "Please provide your final verdict based on all the evidence collected.",
        })
        response = self._call_llm()
        if response:
            return (response.get("content") or "").strip()
        return "Agent could not produce a final verdict."

    def _enrich_input(self, user_input: str) -> str:
        """Detect input type and add context."""
        user_input = user_input.strip()

        expanded = os.path.expanduser(user_input)
        if os.path.isfile(expanded):
            return (
                f"Analyze this email file: {expanded}\n"
                f"The file exists on disk. Use the appropriate tools to analyze it."
            )

        if re.match(r"https?://", user_input, re.IGNORECASE):
            return f"Analyze this URL for phishing indicators: {user_input}"

        if "@" in user_input and "." in user_input.split("@")[-1]:
            return f"Verify this sender: {user_input}"

        if "." in user_input and " " not in user_input and "/" not in user_input:
            return f"Verify this domain: {user_input}"

        return user_input

    def _call_llm(self) -> dict | None:
        """Dispatch to Ollama native or OpenAI-compatible endpoint."""
        if self.is_ollama:
            return self._call_ollama_native()
        return self._call_openai_compat()

    def _call_ollama_native(self) -> dict | None:
        """Call Ollama native /api/chat with tool-calling support."""
        native_url = self.base_url.replace("/v1", "") + "/api/chat"

        body = {
            "model": self.model,
            "messages": self.messages,
            "tools": OLLAMA_TOOLS,
            "stream": False,
            "think": False,
        }

        logger.info("Ollama agent request: model=%s messages=%d", self.model, len(self.messages))

        try:
            req = urllib.request.Request(
                native_url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                result = json.loads(resp.read().decode("utf-8"))

            msg = result.get("message", {})

            # Normalize Ollama tool_calls format to OpenAI format
            tool_calls = msg.get("tool_calls") or []
            normalized_calls = []
            for i, tc in enumerate(tool_calls):
                fn = tc.get("function", {})
                normalized_calls.append({
                    "id": f"call_{i}",
                    "type": "function",
                    "function": {
                        "name": fn.get("name", ""),
                        "arguments": fn.get("arguments", {})
                    },
                })

            return {
                "role": "assistant",
                "content": (msg.get("content") or "").strip(),
                "tool_calls": normalized_calls if normalized_calls else None,
            }
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8")[:500]
            except Exception:
                pass
            logger.error("Ollama agent HTTP %d: %s — %s", e.code, e.reason, body_text)
            return None
        except Exception as e:
            logger.error("Ollama agent error: %s", e)
            return None

    def _call_openai_compat(self) -> dict | None:
        """Call OpenAI-compatible /v1/chat/completions."""
        url = f"{self.base_url.rstrip('/')}/chat/completions"

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body: dict = {
            "messages": self.messages,
            "tools": TOOL_DEFINITIONS,
            "temperature": 0.1,
            "stream": False,
        }
        if self.model:
            body["model"] = self.model

        logger.info("OpenAI-compat agent request: model=%s messages=%d", self.model, len(self.messages))

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                choices = result.get("choices", [])
                if not choices:
                    return None
                return choices[0].get("message", {})
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8")[:500]
            except Exception:
                pass
            logger.error("Agent LLM HTTP %d: %s — %s", e.code, e.reason, body_text)
            return None
        except Exception as e:
            logger.error("Agent LLM error: %s", e)
            return None
