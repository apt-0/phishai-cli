"""phishai sender — verify a sender domain."""

from __future__ import annotations

import argparse

from phishai_cli.output import (
    console,
    print_header,
    print_key_value,
    print_success,
)


def run(args: argparse.Namespace) -> int:
    print_header("Sender Verification")

    from phishai.tools.core import verify_sender

    with console.status("[cyan]Verifying sender...[/]"):
        result = verify_sender(args.target)

    console.print(f"\n  [bold]Domain:[/] {result.domain}")

    # ── WHOIS ──
    if result.whois:
        console.print("\n  [bold]WHOIS[/]")
        w = result.whois
        if hasattr(w, "registrar") and w.registrar:
            print_key_value("Registrar", w.registrar)
        if result.age_days is not None:
            age_color = "red" if result.is_new_domain else "green"
            label = "NEW" if result.is_new_domain else "established"
            print_key_value("Age", f"[{age_color}]{result.age_days} days ({label})[/]")
        if hasattr(w, "creation_date") and w.creation_date:
            print_key_value("Created", w.creation_date)
        if hasattr(w, "country") and w.country:
            print_key_value("Country", w.country)

    # ── DNS ──
    if result.dns:
        console.print("\n  [bold]DNS[/]")
        d = result.dns
        if hasattr(d, "mx_records") and d.mx_records:
            print_key_value("MX", ", ".join(str(r) for r in d.mx_records[:5]))
        if hasattr(d, "spf_record") and d.spf_record:
            print_key_value("SPF", d.spf_record[:100])
        if hasattr(d, "has_dmarc"):
            print_key_value("DMARC", "Yes" if d.has_dmarc else "[yellow]No[/]")
        if hasattr(d, "has_dkim"):
            print_key_value("DKIM", "Yes" if d.has_dkim else "[dim]Unknown[/]")

    # ── BIMI ──
    console.print("\n  [bold]BIMI[/]")
    if result.has_bimi:
        print_success("  BIMI record found")
        if result.has_vmc:
            print_success("  VMC certificate verified")
        else:
            print_key_value("VMC", "[yellow]No verified certificate[/]")
    else:
        print_key_value("BIMI", "[dim]No BIMI record[/]")

    return 0
