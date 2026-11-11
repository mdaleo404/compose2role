"""Transport-neutral role and Compose project name normalization."""

from __future__ import annotations

import re


def normalize_role_name(raw: str) -> str:
    """Derive a deterministic valid Ansible role name."""
    normalized = re.sub(r"[^a-z0-9_]+", "_", raw.lower()).strip("_")
    if not normalized:
        return "compose_project"
    if not normalized[0].isalpha():
        return f"compose_{normalized}"
    return normalized


def normalize_compose_project_name(raw: str) -> str:
    """Derive a deterministic Compose-compatible project name."""
    normalized = re.sub(r"[^a-z0-9_-]+", "", raw.lower()).strip("_-")
    if not normalized:
        return "compose"
    if not normalized[0].isalnum():
        return f"compose_{normalized}"
    return normalized
