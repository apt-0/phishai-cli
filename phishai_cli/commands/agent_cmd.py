"""phishai agent — AI agent that auto-selects tools based on input."""

from __future__ import annotations

import argparse

from phishai_cli.output import (
    console,
    print_error,
    print_header,
    print_key_value,
)


def _resolve_provider(args: argparse.Namespace) -> tuple[str, str]:
    """Resolve provider type and model from shortcut flags.

    Returns (provider_type, model).
    """
    if args.ollama:
        return "ollama", args.ollama
    if args.lmstudio:
        return "lmstudio", args.lmstudio
    if args.openai:
        return "openai", args.openai
    if args.openrouter:
        return "openrouter", args.openrouter

    # No provider specified — default to ollama
    return "ollama", ""


def run(args: argparse.Namespace) -> int:
    provider_type, model = _resolve_provider(args)

    if not model:
        print_error(
            "Specify a model. Examples:\n"
            "  phishai agent --ollama qwen3.5:4b email.eml\n"
            "  phishai agent --openai gpt-4o email.eml\n"
            "  phishai agent --lmstudio qwen3.5 -i"
        )
        return 1

    if args.interactive:
        return _interactive(args, provider_type, model)

    if not args.input:
        print_error("Provide an email file, URL, or prompt. Use -i for interactive mode.")
        return 1

    return _single_shot(args, provider_type, model)


def _single_shot(args: argparse.Namespace, provider_type: str, model: str) -> int:
    """Single-shot agent: analyze input and produce a verdict."""
    print_header("PhishAI Agent")
    print_key_value("Provider", f"{provider_type} / {model}")

    from phishai_cli.agent.core import Agent

    agent = Agent(
        provider_type=provider_type,
        model=model,
        base_url=args.base_url,
        api_key=args.api_key,
    )

    with console.status("[cyan]Agent is thinking...[/]"):
        response = agent.run(args.input)

    console.print(f"\n{response}")
    return 0


def _interactive(args: argparse.Namespace, provider_type: str, model: str) -> int:
    """Interactive chat mode with the agent."""
    print_header("PhishAI Agent (Interactive)")
    print_key_value("Provider", f"{provider_type} / {model}")
    console.print("[dim]Type 'exit' or 'quit' to leave. Drag & drop .eml files or paste URLs.[/]\n")

    from phishai_cli.agent.core import Agent

    agent = Agent(
        provider_type=provider_type,
        model=model,
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
