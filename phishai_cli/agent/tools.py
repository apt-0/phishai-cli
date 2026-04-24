"""Tool definitions for the PhishAI agent.

Each tool wraps an engine function and provides a schema the LLM can use
for tool-calling.  The agent sees the TOOL_DEFINITIONS list and calls
tools by name via execute_tool().
"""

from __future__ import annotations

import json
import os

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "parse_email",
            "description": "Parse a raw email source into structured fields: headers, routing, authentication (SPF/DKIM/DMARC), body, attachments, and IOCs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .eml file to parse",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "quick_scan",
            "description": "Run a fast local-only analysis: parse, red flags, content triggers, NLP signals, risk scoring. No external APIs. Use this as a first pass.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .eml file to scan",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "deep_analyze",
            "description": "Full analysis with enrichment (WHOIS, DNS, VirusTotal) and LLM verdict. Use after quick_scan when deeper investigation is needed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .eml file",
                    },
                    "services": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Enrichment services: whois, dns, virustotal, abuseipdb",
                    },
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_url",
            "description": "Analyze a URL for phishing: visit with headless browser, capture screenshot, detect login forms, brand impersonation, redirects, and compute risk score.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to analyze",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_sender",
            "description": "Verify a sender domain: WHOIS age, DNS records (SPF/DKIM/DMARC), BIMI brand verification.",
            "parameters": {
                "type": "object",
                "properties": {
                    "email_or_domain": {
                        "type": "string",
                        "description": "Email address or domain to verify",
                    },
                },
                "required": ["email_or_domain"],
            },
        },
    },
]


def execute_tool(name: str, arguments: dict) -> str:
    """Execute a tool by name and return a JSON string result."""
    try:
        if name == "parse_email":
            raw = _read_eml(arguments["file_path"])
            if raw is None:
                return json.dumps({"error": f"Cannot read file: {arguments['file_path']}"})
            from phishai.tools.core import parse_email
            result = parse_email(raw)
            return _serialize(result)

        if name == "quick_scan":
            raw = _read_eml(arguments["file_path"])
            if raw is None:
                return json.dumps({"error": f"Cannot read file: {arguments['file_path']}"})
            from phishai.tools.core import quick_scan
            result = quick_scan(raw)
            return _serialize(result)

        if name == "deep_analyze":
            raw = _read_eml(arguments["file_path"])
            if raw is None:
                return json.dumps({"error": f"Cannot read file: {arguments['file_path']}"})
            from phishai.tools.core import deep_analyze
            result = deep_analyze(raw, services=arguments.get("services", ["whois", "dns"]))
            return _serialize(result)

        if name == "analyze_url":
            from phishai.tools.core import analyze_url
            result = analyze_url(arguments["url"])
            # Exclude screenshot from agent context (too large)
            d = result.model_dump() if hasattr(result, "model_dump") else vars(result)
            d.pop("screenshot_b64", None)
            return json.dumps(d, default=str, ensure_ascii=False)

        if name == "verify_sender":
            from phishai.tools.core import verify_sender
            result = verify_sender(arguments["email_or_domain"])
            return _serialize(result)

        return json.dumps({"error": f"Unknown tool: {name}"})

    except Exception as e:
        return json.dumps({"error": str(e)})


def _read_eml(path: str) -> str | None:
    """Read an .eml file, returning None on error."""
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _serialize(obj) -> str:
    """Serialize a Pydantic model or dict to JSON string."""
    if hasattr(obj, "model_dump"):
        d = obj.model_dump()
    elif hasattr(obj, "__dict__"):
        d = vars(obj)
    else:
        d = obj
    return json.dumps(d, default=str, ensure_ascii=False)
