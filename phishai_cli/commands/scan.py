"""phishai scan — quick local-only email analysis."""

from __future__ import annotations

import argparse

from phishai_cli.output import (
    console,
    print_header,
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
        print_key_value("From", f"{p.from_display or ''} <{p.from_address or 'unknown'}>")
        print_key_value("To", p.to_address or "unknown")
        print_key_value("Subject", p.subject or "(no subject)")
        print_key_value("Date", p.date or "unknown")

        # Auth results
        if p.auth_results:
            console.print("\n  [bold]Authentication[/]")
            for auth in p.auth_results:
                color = "green" if auth.result == "pass" else "red"
                console.print(f"    [{color}]{auth.method.upper()}:[/] {auth.result}")

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
        nlp_data = nlp.model_dump() if hasattr(nlp, "model_dump") else {}
        # Show only signals above threshold
        active = {k: v for k, v in nlp_data.items() if isinstance(v, (int, float)) and v >= 0.3}
        if active:
            console.print(f"\n  [bold]NLP Signals[/]")
            for signal, score in sorted(active.items(), key=lambda x: -x[1]):
                bar_len = int(score * 20)
                color = "red" if score >= 0.7 else "yellow" if score >= 0.4 else "cyan"
                bar = f"[{color}]{'#' * bar_len}{'.' * (20 - bar_len)}[/]"
                console.print(f"    {signal:<28} {bar} {score:.2f}")

    # ── Risk ──
    if result.risk:
        print_risk_score(result.risk.risk_score, label=f"Risk Score ({result.risk.risk_level})")

        if result.risk.triggered_rules:
            console.print(f"  [bold]Triggered Rules[/]")
            for rule in result.risk.triggered_rules:
                weight = rule.get("weight", 0) if isinstance(rule, dict) else getattr(rule, "weight", 0)
                desc = rule.get("description", "") if isinstance(rule, dict) else getattr(rule, "description", "")
                evidence = rule.get("evidence", "") if isinstance(rule, dict) else getattr(rule, "evidence", "")
                color = "red" if weight > 0 else "green"
                sign = "+" if weight > 0 else ""
                console.print(f"    [{color}]{sign}{weight:.2f}[/] {desc}")
                if evidence:
                    console.print(f"         [dim]{evidence}[/]")

        if result.risk.score_breakdown:
            breakdown = result.risk.score_breakdown
            bd = breakdown if isinstance(breakdown, dict) else (breakdown.model_dump() if hasattr(breakdown, "model_dump") else {})
            parts = [f"{k}: {v:.3f}" for k, v in bd.items() if v]
            if parts:
                console.print(f"\n  [dim]Breakdown: {' | '.join(parts)}[/]")

    return 0
