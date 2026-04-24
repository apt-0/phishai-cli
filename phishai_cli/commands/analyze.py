"""phishai analyze — full deep analysis with enrichment + LLM."""

from __future__ import annotations

import argparse

from phishai_cli.output import (
    console,
    make_table,
    print_error,
    print_header,
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
        print_key_value("From", f"{p.from_display or ''} <{p.from_address or 'unknown'}>")
        print_key_value("To", p.to_address or "unknown")
        print_key_value("Subject", p.subject or "(no subject)")

        if p.auth_results:
            auth_summary = ", ".join(
                f"{a.method.upper()}={a.result}" for a in p.auth_results
            )
            print_key_value("Auth", auth_summary)

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
            found = val.found if hasattr(val, "found") else bool(val)
            status_color = "green" if found else "dim"
            status_text = "found" if found else "empty"
            table.add_row(ioc, svc, f"[{status_color}]{status_text}[/]")
        console.print(table)

    # ── ML ──
    if result.ml:
        console.print("\n  [bold]ML Classification[/]")
        if hasattr(result.ml, "label"):
            color = "red" if "phish" in str(result.ml.label).lower() else "green"
            console.print(f"    Label: [{color} bold]{result.ml.label}[/]")
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
        risk = result.scan.risk
        print_risk_score(risk.risk_score, label=f"Risk Score ({risk.risk_level})")

        if risk.triggered_rules:
            console.print(f"  [bold]Triggered Rules[/]")
            for rule in risk.triggered_rules:
                weight = rule.get("weight", 0) if isinstance(rule, dict) else getattr(rule, "weight", 0)
                desc = rule.get("description", "") if isinstance(rule, dict) else getattr(rule, "description", "")
                color = "red" if weight > 0 else "green"
                sign = "+" if weight > 0 else ""
                console.print(f"    [{color}]{sign}{weight:.2f}[/] {desc}")

    return 0
