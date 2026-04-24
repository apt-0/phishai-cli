"""Provider resolution from CLI shortcut flags."""

from __future__ import annotations

import argparse
from typing import Optional


def resolve_llm_provider(args: argparse.Namespace) -> Optional[dict]:
    """Resolve --ollama/--lmstudio/--openai/--openrouter flags into a provider config dict.

    Returns None if no provider flag is set.
    """
    provider_type = None
    model = None

    if getattr(args, "ollama", None):
        provider_type, model = "ollama", args.ollama
    elif getattr(args, "lmstudio", None):
        provider_type, model = "lmstudio", args.lmstudio
    elif getattr(args, "openai", None):
        provider_type, model = "openai", args.openai
    elif getattr(args, "openrouter", None):
        provider_type, model = "openrouter", args.openrouter

    if not provider_type:
        return None

    from phishai.llm.provider import make_provider_config

    return make_provider_config(
        provider_type=provider_type,
        api_key=getattr(args, "api_key", ""),
        model=model,
    )
