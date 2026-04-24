"""phishai agent — AI agent that auto-selects tools based on input."""

from __future__ import annotations

import argparse

from phishai_cli.output import (
    console,
    print_error,
    print_header,
)


def run(args: argparse.Namespace) -> int:
    if args.interactive:
        return _interactive(args)

    if not args.input:
        print_error("Provide an email file, URL, or prompt. Use -i for interactive mode.")
        return 1

    return _single_shot(args)


def _single_shot(args: argparse.Namespace) -> int:
    """Single-shot agent: analyze input and produce a verdict."""
    print_header("PhishAI Agent")

    from phishai_cli.agent.core import Agent

    agent = Agent(
        provider_type=args.provider,
        model=args.model,
        base_url=args.base_url,
        api_key=args.api_key,
    )

    with console.status("[cyan]Agent is thinking...[/]"):
        response = agent.run(args.input)

    console.print(f"\n{response}")
    return 0


def _interactive(args: argparse.Namespace) -> int:
    """Interactive chat mode with the agent."""
    print_header("PhishAI Agent (Interactive)")
    console.print("[dim]Type 'exit' or 'quit' to leave. Drag & drop .eml files or paste URLs.[/]\n")

    from phishai_cli.agent.core import Agent

    agent = Agent(
        provider_type=args.provider,
        model=args.model,
        base_url=args.base_url,
        api_key=args.api_key,
    )

    while True:
        try:
            user_input = console.input("[bold cyan]phishai>[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/]")
            return 0

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            console.print("[dim]Goodbye.[/]")
            return 0

        with console.status("[cyan]Agent is thinking...[/]"):
            response = agent.run(user_input)

        console.print(f"\n{response}\n")

    return 0
