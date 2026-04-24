"""phishai report — generate HTML report from email analysis."""

from __future__ import annotations

import argparse

from phishai_cli.output import (
    console,
    print_error,
    print_header,
    print_success,
    read_eml_file,
)


def run(args: argparse.Namespace) -> int:
    raw = read_eml_file(args.file)
    if raw is None:
        return 1

    print_header("Report Generation")

    from phishai.tools.core import deep_analyze, generate_report

    # Run analysis first
    with console.status("[cyan]Analyzing email...[/]"):
        analysis = deep_analyze(
            raw,
            services=["whois", "dns"],
            llm_model=args.llm_model or None,
        )

    # We need an AnalysisResult for generate_report — reconstruct it
    from phishai.models.engine import AnalysisResult

    analysis_result = AnalysisResult(
        parsed=analysis.scan.parsed if analysis.scan else None,
        red_flags=analysis.scan.red_flags if analysis.scan else None,
        content_triggers=analysis.scan.content_triggers if analysis.scan else None,
        nlp_signals=analysis.scan.nlp_signals if analysis.scan else None,
        risk=analysis.scan.risk if analysis.scan else None,
        enrichment=analysis.enrichment,
        ml_result=analysis.ml,
        llm=analysis.llm,
    )

    with console.status("[cyan]Generating report...[/]"):
        html = generate_report(analysis_result)

    output_path = args.output
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print_success(f"Report saved to {output_path} ({len(html):,} bytes)")
    except Exception as e:
        print_error(f"Cannot write report: {e}")
        return 1

    return 0
