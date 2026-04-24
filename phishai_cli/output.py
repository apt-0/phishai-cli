"""Terminal output formatting with Rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()
err_console = Console(stderr=True)


def print_header(title: str) -> None:
    console.print(Panel(f"[bold cyan]{title}[/]", border_style="cyan"))


def print_error(msg: str) -> None:
    err_console.print(f"[bold red]Error:[/] {msg}")


def print_success(msg: str) -> None:
    console.print(f"[bold green]{msg}[/]")


def print_risk_score(score: float, label: str = "Risk Score") -> None:
    if score >= 0.7:
        color = "red"
        level = "HIGH"
    elif score >= 0.4:
        color = "yellow"
        level = "MEDIUM"
    elif score >= 0.15:
        color = "cyan"
        level = "LOW"
    else:
        color = "green"
        level = "SAFE"

    bar_len = int(score * 30)
    bar = f"[{color}]{'█' * bar_len}{'░' * (30 - bar_len)}[/]"

    console.print(f"\n  {label}: [{color} bold]{score:.0%} {level}[/]")
    console.print(f"  {bar}\n")


def print_indicators(indicators: list[str], title: str = "Risk Indicators") -> None:
    if not indicators:
        return
    console.print(f"  [bold]{title}:[/]")
    for ind in indicators:
        console.print(f"    [dim]•[/] {ind}")
    console.print()


def print_key_value(key: str, value, indent: int = 2) -> None:
    pad = " " * indent
    console.print(f"{pad}[bold]{key}:[/] {value}")


def make_table(*columns: str, title: str = "") -> Table:
    table = Table(title=title, show_header=True, header_style="bold cyan")
    for col in columns:
        table.add_column(col)
    return table


def read_eml_file(path: str) -> str | None:
    """Read an .eml file and return its content, or None on error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        print_error(f"File not found: {path}")
        return None
    except Exception as e:
        print_error(f"Cannot read file: {e}")
        return None
