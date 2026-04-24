"""phishai analyze — full deep analysis with enrichment + LLM."""

from __future__ import annotations

import argparse

from phishai_cli.output import (
    console,
    make_table,
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

    print_header("Deep Analysis")

    api_keys = {}
    if args.vt_key:
        api_keys["virustotal"] = args.vt_key

    from phishai.tools.core import deep_analyze

    with console.status("[cyan]Running deep analysis...[/]"):
        result = deep_analyze(
            raw,
            services=args.services,
            api_keys=api_keys,
            llm_model=args.llm_model or None,
            llm_mode=args.llm_mode,
        )

    # ── Quick scan summary ──
    if result.scan and result.scan.parsed:
        p = result.scan.parsed
        console.print("\n  [bold]Email Summary[/]")
        print_key_value("From", p.sender or "unknown")
        print_key_value("Subject", p.subject or "(no subject)")

    if result.scan and result.scan.red_flags:
        console.print(f"\n  [bold red]Red Flags ({len(result.scan.red_flags)})[/]")
        for rf in result.scan.red_flags:
            desc = rf.description if hasattr(rf, "description") else str(rf)
            console.print(f"    [red]●[/] {desc}")

    # ── Enrichment ──
    if result.enrichment:
        console.print("\n  [bold]Enrichment Results[/]")
        table = make_table("IOC", "Service", "Status")
        for key, val in result.enrichment.items():
            parts = key.split(":")
            ioc = parts[1] if len(parts) > 1 else key
            svc = parts[2] if len(parts) > 2 else "?"
            status = "found" if val else "empty"
            table.add_row(ioc, svc, status)
        console.print(table)

    # ── ML ──
    if result.ml:
        console.print("\n  [bold]ML Classification[/]")
        if hasattr(result.ml, "label"):
            print_key_value("Label", result.ml.label)
        if hasattr(result.ml, "confidence"):
            print_key_value("Confidence", f"{result.ml.confidence:.2%}")

    # ── LLM ──
    if result.llm:
        console.print("\n  [bold]LLM Verdict[/]")
        if hasattr(result.llm, "verdict"):
            color = "red" if "phish" in str(result.llm.verdict).lower() else "green"
            console.print(f"    [{color} bold]{result.llm.verdict}[/]")
        if hasattr(result.llm, "reasoning"):
            console.print(f"    [dim]{result.llm.reasoning}[/]")

    # ── Risk ──
    if result.scan and result.scan.risk:
        print_risk_score(result.scan.risk.score)
        print_indicators(
            result.scan.risk.indicators if hasattr(result.scan.risk, "indicators") else []
        )

    return 0
