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
        records = d.records if hasattr(d, "records") and d.records else {}

        if records.get("MX"):
            print_key_value("MX", ", ".join(str(r) for r in records["MX"][:5]))
        if records.get("A"):
            print_key_value("A", ", ".join(records["A"][:4]))
        if records.get("AAAA"):
            print_key_value("AAAA", ", ".join(records["AAAA"][:2]))
        if records.get("NS"):
            print_key_value("NS", ", ".join(records["NS"][:4]))

        # SPF — from dedicated SPF field or TXT records
        txt_records = records.get("TXT", [])
        spf_records = records.get("SPF", [])
        spf = spf_records[0] if spf_records else next(
            (t for t in txt_records if "v=spf1" in str(t).lower()), None
        )

        # DMARC — from dedicated DMARC field or TXT records
        dmarc_records = records.get("DMARC", [])
        dmarc = dmarc_records[0] if dmarc_records else next(
            (t for t in txt_records if "v=dmarc1" in str(t).lower()), None
        )

        if spf:
            print_key_value("SPF", f"[green]Yes[/] — {str(spf)[:120]}")
        else:
            print_key_value("SPF", "[yellow]Not found[/]")
        if dmarc:
            print_key_value("DMARC", f"[green]Yes[/] — {str(dmarc)[:120]}")
        else:
            print_key_value("DMARC", "[yellow]Not found[/]")

    # ── BIMI ──
    if result.bimi:
        console.print("\n  [bold]BIMI[/]")
        if result.has_bimi:
            print_success("  BIMI record found")
            if result.bimi.logo_url:
                print_key_value("Logo", result.bimi.logo_url)
            if result.has_vmc:
                print_success("  VMC certificate verified")
                if result.bimi.vmc_url:
                    print_key_value("VMC URL", result.bimi.vmc_url)
            else:
                print_key_value("VMC", "[yellow]No verified certificate[/]")
        else:
            print_key_value("BIMI", "[dim]No BIMI record[/]")

    return 0
