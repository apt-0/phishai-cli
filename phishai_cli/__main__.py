"""Entry point: ``python -m phishai_cli`` or ``phishai`` (console script)."""

from __future__ import annotations

import argparse
import sys

from phishai_cli import __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishai",
        description="PhishAI CLI — AI-powered phishing analysis agent",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"phishai-cli {__version__}",
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan (quick_scan) ──────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Quick local-only email scan")
    p_scan.add_argument("file", help="Path to .eml file")

    # ── analyze (deep_analyze) ─────────────────────────────────────
    p_analyze = sub.add_parser("analyze", help="Full deep analysis with enrichment + LLM")
    p_analyze.add_argument("file", help="Path to .eml file")
    p_analyze.add_argument("--services", nargs="*", default=["whois", "dns"],
                           help="Enrichment services (default: whois dns)")
    p_analyze.add_argument("--vt-key", default="", help="VirusTotal API key")
    p_analyze.add_argument("--llm-model", default="", help="Path to GGUF model file")
    p_analyze.add_argument("--llm-mode", default="quick", choices=["quick", "deep"],
                           help="LLM analysis depth (default: quick)")

    # ── url (analyze_url) ──────────────────────────────────────────
    p_url = sub.add_parser("url", help="Analyze a URL for phishing indicators")
    p_url.add_argument("target_url", help="URL to analyze")
    p_url.add_argument("--vision-provider", default="", help="Vision LLM provider type")
    p_url.add_argument("--vision-model", default="", help="Vision model name")
    p_url.add_argument("--vision-url", default="", help="Vision API base URL")
    p_url.add_argument("--timeout", type=int, default=20, help="Navigation timeout (seconds)")

    # ── sender (verify_sender) ─────────────────────────────────────
    p_sender = sub.add_parser("sender", help="Verify a sender domain (WHOIS/DNS/BIMI)")
    p_sender.add_argument("target", help="Email address or domain")

    # ── report (generate_report) ───────────────────────────────────
    p_report = sub.add_parser("report", help="Generate HTML report from email analysis")
    p_report.add_argument("file", help="Path to .eml file")
    p_report.add_argument("-o", "--output", default="report.html",
                          help="Output file (default: report.html)")
    p_report.add_argument("--llm-model", default="", help="Path to GGUF model file")

    # ── agent (AI agent mode) ──────────────────────────────────────
    p_agent = sub.add_parser("agent", help="AI agent — auto-selects tools based on input")
    p_agent.add_argument("input", nargs="?", default="",
                         help="Email file, URL, or natural language prompt")
    p_agent.add_argument("--provider", default="ollama",
                         help="LLM provider (ollama, openai, openrouter, lmstudio)")
    p_agent.add_argument("--model", default="", help="Model name")
    p_agent.add_argument("--base-url", default="", help="API base URL")
    p_agent.add_argument("--api-key", default="", help="API key")
    p_agent.add_argument("--interactive", "-i", action="store_true",
                         help="Interactive chat mode")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    # Dispatch to command handlers
    if args.command == "scan":
        from phishai_cli.commands.scan import run
        return run(args)

    if args.command == "analyze":
        from phishai_cli.commands.analyze import run
        return run(args)

    if args.command == "url":
        from phishai_cli.commands.url import run
        return run(args)

    if args.command == "sender":
        from phishai_cli.commands.sender import run
        return run(args)

    if args.command == "report":
        from phishai_cli.commands.report import run
        return run(args)

    if args.command == "agent":
        from phishai_cli.commands.agent_cmd import run
        return run(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
