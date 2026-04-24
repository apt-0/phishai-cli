"""PhishAI Agent — LLM-powered tool orchestrator.

The agent receives user input (email file, URL, or natural language),
decides which engine tools to call and in what order, then produces
a final verdict in natural language.

Uses OpenAI-compatible tool-calling API (works with Ollama, OpenAI,
OpenRouter, LM Studio).
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

MAX_TOOL_ROUNDS = 8


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
        self.base_url = base_url or preset.get("base_url", "")
        self.api_key = api_key
        self.model = model or preset.get("default_model", "")
        self.messages: list[dict] = []

    def run(self, user_input: str) -> str:
        """Process user input through the agent loop.

        Returns a final natural-language response.
        """
        # Detect input type and enrich the prompt
        enriched = self._enrich_input(user_input)

        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": enriched},
        ]

        for _round in range(MAX_TOOL_ROUNDS):
            response = self._chat_completion()
            if response is None:
                return "Error: could not get a response from the LLM."

            # Check if the model wants to call tools
            tool_calls = response.get("tool_calls") or []
            content = (response.get("content") or "").strip()

            if not tool_calls:
                # No more tool calls — this is the final answer
                return content if content else "Analysis complete — no further findings."

            # Execute each tool call
            self.messages.append(response)

            for tc in tool_calls:
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                try:
                    tool_args = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    tool_args = {}

                logger.info("Agent calling tool: %s(%s)", tool_name, tool_args)

                result_str = execute_tool(tool_name, tool_args)

                # Truncate very large results to keep context manageable
                if len(result_str) > 8000:
                    result_str = result_str[:8000] + "\n... (truncated)"

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": result_str,
                })

        # Exhausted rounds — ask for final verdict
        self.messages.append({
            "role": "user",
            "content": "Please provide your final verdict based on all the evidence collected.",
        })
        response = self._chat_completion()
        if response:
            return (response.get("content") or "").strip()
        return "Agent could not produce a final verdict."

    def _enrich_input(self, user_input: str) -> str:
        """Detect input type and add context to help the agent."""
        user_input = user_input.strip()

        # File path — check if it's an .eml file
        expanded = os.path.expanduser(user_input)
        if os.path.isfile(expanded):
            return (
                f"Analyze this email file: {expanded}\n"
                f"The file exists on disk. Use the appropriate tools to analyze it."
            )

        # URL
        if re.match(r"https?://", user_input, re.IGNORECASE):
            return f"Analyze this URL for phishing indicators: {user_input}"

        # Email address
        if "@" in user_input and "." in user_input.split("@")[-1]:
            return f"Verify this sender: {user_input}"

        # Domain (no spaces, has a dot)
        if "." in user_input and " " not in user_input and "/" not in user_input:
            return f"Verify this domain: {user_input}"

        # Natural language — pass through
        return user_input

    def _chat_completion(self) -> dict | None:
        """Call the LLM with tool definitions."""
        if not self.base_url:
            logger.error("No base_url configured for agent LLM")
            return None

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

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=180) as resp:
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
