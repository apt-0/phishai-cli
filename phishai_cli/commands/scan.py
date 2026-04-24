"""phishai scan — quick local-only email analysis."""

from __future__ import annotations

import argparse

from phishai_cli.output import (
    console,
    print_error,
    print_header,
    print_indicators,
    print_key_value,
    print_risk_score,
    read_eml_file,
)


def run(args: argparse.Namespace) -> int:
    raw = read_eml_file(args.file)
    if raw is None:
        return 1

    print_header("Quick Scan")

    from phishai.tools.core import quick_scan

    with console.status("[cyan]Scanning...[/]"):
        result = quick_scan(raw)

    # ── Parsed info ──
    if result.parsed:
        p = result.parsed
        console.print("\n  [bold]Email Summary[/]")
        print_key_value("From", p.sender or "unknown")
        print_key_value("To", ", ".join(p.recipients) if p.recipients else "unknown")
        print_key_value("Subject", p.subject or "(no subject)")
        print_key_value("Date", p.date or "unknown")
        if p.auth:
            print_key_value("SPF", p.auth.spf_result or "none")
            print_key_value("DKIM", p.auth.dkim_result or "none")
            print_key_value("DMARC", p.auth.dmarc_result or "none")

    # ── Red flags ──
    if result.red_flags:
        console.print(f"\n  [bold red]Red Flags ({len(result.red_flags)})[/]")
        for rf in result.red_flags:
            sev = rf.severity if hasattr(rf, "severity") else "medium"
            color = {"high": "red", "medium": "yellow", "low": "cyan"}.get(sev, "white")
            desc = rf.description if hasattr(rf, "description") else str(rf)
            console.print(f"    [{color}]●[/] {desc}")

    # ── Content triggers ──
    if result.content_triggers:
        triggers = result.content_triggers
        cats = triggers.categories if hasattr(triggers, "categories") else []
        if cats:
            console.print(f"\n  [bold yellow]Content Triggers[/]")
            for cat in cats:
                name = cat.name if hasattr(cat, "name") else str(cat)
                count = cat.match_count if hasattr(cat, "match_count") else ""
                console.print(f"    [yellow]●[/] {name} ({count} matches)")

    # ── NLP signals ──
    if result.nlp_signals:
        nlp = result.nlp_signals
        console.print(f"\n  [bold]NLP Signals[/]")
        if hasattr(nlp, "phishing_score"):
            print_key_value("Phishing score", f"{nlp.phishing_score:.2f}")
        if hasattr(nlp, "urgency_score"):
            print_key_value("Urgency score", f"{nlp.urgency_score:.2f}")
        if hasattr(nlp, "sentiment_label"):
            print_key_value("Sentiment", nlp.sentiment_label)

    # ── Risk ──
    if result.risk:
        print_risk_score(result.risk.score)
        print_indicators(
            result.risk.indicators if hasattr(result.risk, "indicators") else []
        )

    return 0
