"""Captured Compose source metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FileMetadata:
    """Ownership and mode captured with one source file."""

    mode: int
    uid: int
    gid: int
