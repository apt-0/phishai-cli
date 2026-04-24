"""phishai url — analyze a URL for phishing indicators."""

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
)


def run(args: argparse.Namespace) -> int:
    from phishai_cli.providers import resolve_llm_provider

    vision_provider = resolve_llm_provider(args)

    print_header("URL Analysis")
    if vision_provider:
        print_key_value("Vision", f"{vision_provider['type']} / {vision_provider['model']}")

    from phishai.tools.core import analyze_url

    with console.status("[cyan]Fetching and analyzing URL...[/]"):
        result = analyze_url(
            args.target_url,
            timeout=args.timeout,
            vision_provider=vision_provider,
        )

    # ── Basic info ──
    console.print("\n  [bold]URL Info[/]")
    print_key_value("URL", result.url)
    if result.final_url != result.url:
        print_key_value("Final URL", result.final_url)
    print_key_value("Status", result.status_code or "N/A")
    print_key_value("Domain", result.domain)
    print_key_value("HTTPS", "Yes" if result.is_https else "[red]No[/]")
    print_key_value("Browser", "Playwright" if result.browser_used else "httpx (fallback)")
    if result.page_title:
        print_key_value("Title", result.page_title)

    # ── Redirects ──
    if result.redirect_chain:
        console.print(f"\n  [bold]Redirect Chain ({result.redirect_count})[/]")
        for hop in result.redirect_chain:
            console.print(f"    [dim]→[/] [{hop.status_code}] {hop.url}")

    # ── Forms ──
    if result.forms:
        console.print(f"\n  [bold]Forms Detected ({len(result.forms)})[/]")
        for f in result.forms:
            login_tag = " [red bold]LOGIN[/]" if f.is_login_form else ""
            console.print(f"    [dim]•[/] {f.method.upper()} → {f.action or '(self)'}{login_tag}")
            if f.has_password_field:
                console.print(f"      [yellow]password field[/]")

    # ── Brand impersonation ──
    if result.brand_matches:
        console.print(f"\n  [bold]Brand Detection[/]")
        table = make_table("Brand", "Confidence", "Evidence")
        for bm in result.brand_matches:
            conf_color = "red" if bm.confidence >= 0.6 else "yellow"
            table.add_row(
                bm.brand,
                f"[{conf_color}]{bm.confidence:.0%}[/]",
                ", ".join(bm.evidence[:3]) if bm.evidence else "",
            )
        console.print(table)
        if result.likely_impersonation:
            console.print("    [red bold]⚠ Likely brand impersonation[/]")

    # ── AI Vision ──
    if result.vision:
        v = result.vision
        console.print(f"\n  [bold]AI Vision Analysis[/]")
        print_key_value("Page type", v.page_type)
        if v.detected_brand:
            print_key_value("Brand", f"{v.detected_brand} ({v.brand_confidence:.0%})")
        phish_color = "red" if v.is_phishing else "green"
        print_key_value("Phishing", f"[{phish_color}]{v.is_phishing}[/] ({v.phishing_confidence:.0%})")
        if v.visual_indicators:
            console.print(f"    [dim]Indicators: {', '.join(v.visual_indicators[:5])}[/]")
        if v.reasoning:
            console.print(f"    [dim]{v.reasoning}[/]")

    # ── Screenshot ──
    if result.screenshot_b64:
        console.print(f"\n  [dim]Screenshot captured ({len(result.screenshot_b64) // 1024} KB base64)[/]")

    # ── Flags ──
    flags = []
    if result.is_shortener:
        flags.append("[yellow]URL shortener[/]")
    if result.is_ip_based:
        flags.append("[red]IP-based URL[/]")
    if result.has_suspicious_tld:
        flags.append("[yellow]Suspicious TLD[/]")
    if flags:
        console.print(f"\n  [bold]Flags:[/] {' | '.join(flags)}")

    # ── Risk ──
    print_risk_score(result.risk_score)
    print_indicators(result.risk_indicators)

    # ── Error ──
    if result.error:
        print_error(result.error)

    return 0
