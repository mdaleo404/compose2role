"""Compare current captured source hashes with generated-role provenance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from compose2role.remote_emit import (
    normalized_compose_hash,
    normalized_dotenv_hash,
    normalized_file_secret_hash,
)
from compose2role.resolve import ProjectDrift, ProjectSnapshot, ResolvedProject

_PROVENANCE_FILE = ".compose2role.json"


def inspect_drift(project: ResolvedProject, role_directory: Path) -> ProjectDrift:
    """Return the value-free drift state for one project and its role directory."""
    role = role_directory.name
    if not role_directory.exists():
        return ProjectDrift("missing", role=role, reason="role has not been generated")
    if not role_directory.is_dir():
        return ProjectDrift("unmanaged", role=role, reason="role path is not a directory")
    provenance_path = role_directory / _PROVENANCE_FILE
    if not provenance_path.is_file():
        return ProjectDrift(
            "unmanaged", role=role, reason="role has no .compose2role.json provenance"
        )

    try:
        document: object = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ProjectDrift(
            "unmanaged", role=role, reason="role provenance is unreadable"
        )
    if not isinstance(document, dict):
        return ProjectDrift(
            "unmanaged", role=role, reason="role provenance is unreadable"
        )
    files = document.get("files")
    if not isinstance(files, dict):
        return ProjectDrift(
            "unmanaged", role=role, reason="role provenance has no file hashes"
        )

    changed: set[str] = set()
    recorded: set[str] = set()
    for path, entry in files.items():
        if not isinstance(path, str) or not isinstance(entry, dict):
            return ProjectDrift(
                "unmanaged", role=role, reason="role provenance has invalid file hashes"
            )
        expected = entry.get("sha256")
        if not isinstance(expected, str):
            return ProjectDrift(
                "unmanaged", role=role, reason="role provenance has invalid file hashes"
            )
        recorded.add(path)
        actual = _current_hash(project.source, PurePosixPath(path), entry.get("redacted") is True)
        if actual != expected:
            changed.add(path)

    changed.update(_source_paths(project.source) - recorded)
    if changed:
        return ProjectDrift(
            "source changed", role=role, changed=tuple(sorted(changed))
        )
    return ProjectDrift("unchanged", role=role)


def _current_hash(
    snapshot: ProjectSnapshot, relative_path: PurePosixPath, redacted: bool
) -> str | None:
    for source in snapshot.files:
        if source.relative_path == relative_path:
            if redacted:
                return normalized_compose_hash(source.content)
            return hashlib.sha256(source.content).hexdigest()
    for source in snapshot.dotenv_files:
        if source.relative_path == relative_path:
            if redacted:
                return normalized_dotenv_hash(source.content)
            return hashlib.sha256(source.content).hexdigest()
    for file_secret in snapshot.file_secrets:
        if file_secret.source.relative_path == relative_path:
            if redacted:
                return normalized_file_secret_hash(file_secret.source.metadata)
            return hashlib.sha256(file_secret.source.content).hexdigest()
    return None


def _source_paths(snapshot: ProjectSnapshot) -> set[str]:
    paths = {str(source.relative_path) for source in snapshot.files}
    paths.update(str(source.relative_path) for source in snapshot.dotenv_files)
    paths.update(str(file_secret.source.relative_path) for file_secret in snapshot.file_secrets)
    return paths
