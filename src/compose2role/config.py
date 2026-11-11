"""Discover and validate the repository configuration file."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from compose2role.errors import ConfigurationError

CONFIG_FILENAME = ".compose2role.toml"
ANSIBLE_CONFIG_FILENAME = "ansible.cfg"

_DEFAULT_KEYS = frozenset(
    {
        "output",
        "sops_config",
        "secret_policy",
    }
)
_HOST_KEYS = frozenset({"docker_context", "sudo"})


@dataclass(frozen=True)
class HostProfile:
    """Per-host settings that override repository defaults."""

    sudo: bool | None = None
    docker_context: str | None = None


@dataclass(frozen=True)
class RepositoryConfig:
    """A validated repository configuration rooted at a directory."""

    root: Path
    path: Path | None = None
    output: Path | None = None
    sops_config: Path | None = None
    secret_policy: Path | None = None
    hosts: Mapping[str, HostProfile] = field(default_factory=dict)

    def host(self, name: str | None) -> HostProfile:
        """Return the selected host profile, or an empty profile."""
        if name is None:
            return HostProfile()
        return self.hosts.get(name, HostProfile())


def find_repository_config(start: Path | None = None) -> Path | None:
    """Find the nearest `.compose2role.toml`, then the nearest `ansible.cfg`."""
    for filename in (CONFIG_FILENAME, ANSIBLE_CONFIG_FILENAME):
        found = find_file_upwards(start, filename)
        if found is not None:
            return found
    return None


def find_file_upwards(start: Path | None, filename: str) -> Path | None:
    """Find FILENAME in START or its nearest ancestor directory."""
    for directory in ancestor_directories(start):
        candidate = directory / filename
        if candidate.is_file():
            return candidate
    return None


def ancestor_directories(start: Path | None = None) -> tuple[Path, ...]:
    """Return START and each ancestor, treating a non-existent path as a directory."""
    anchor = (start if start is not None else Path.cwd()).expanduser().resolve()
    if anchor.is_file():
        anchor = anchor.parent
    directories: list[Path] = []
    current = anchor
    while True:
        directories.append(current)
        if current == current.parent:
            return tuple(directories)
        current = current.parent


def load_repository_config(
    explicit_path: Path | None = None,
    *,
    start: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> RepositoryConfig:
    """Load the selected configuration, falling back to a discovered config root."""
    environment = os.environ if environ is None else environ
    selected_path = explicit_path
    if selected_path is None:
        environment_path = environment.get("COMPOSE2ROLE_CONFIG")
        selected_path = Path(environment_path) if environment_path else None
    if selected_path is None:
        selected_path = find_repository_config(start)
    if selected_path is None:
        root = (start if start is not None else Path.cwd()).expanduser().resolve()
        return RepositoryConfig(root=root)

    selected_path = selected_path.expanduser()
    if not selected_path.is_file():
        raise ConfigurationError(f"configuration file is unreadable: {selected_path}")
    if selected_path.name == ANSIBLE_CONFIG_FILENAME:
        return RepositoryConfig(root=selected_path.parent.resolve(), path=selected_path)
    return _load_toml(selected_path)


def _load_toml(path: Path) -> RepositoryConfig:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ConfigurationError(f"configuration file is unreadable: {path}") from error
    try:
        document: object = tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        raise ConfigurationError(f"configuration file is not valid TOML: {path}") from error

    root = path.parent.resolve()
    settings = _mapping(document, f"configuration file must be a table: {path}")
    unknown = sorted(set(settings) - {"defaults", "hosts"})
    if unknown:
        raise ConfigurationError(f"unknown configuration key in {path}: {unknown[0]}")

    defaults = _mapping(
        settings.get("defaults", {}), f"configuration defaults must be a table: {path}"
    )
    unknown_defaults = sorted(set(defaults) - _DEFAULT_KEYS)
    if unknown_defaults:
        raise ConfigurationError(
            f"unknown configuration key in {path}: {unknown_defaults[0]}"
        )

    return RepositoryConfig(
        root=root,
        path=path,
        output=_path_setting(defaults, "output", root, path),
        sops_config=_path_setting(defaults, "sops_config", root, path),
        secret_policy=_path_setting(defaults, "secret_policy", root, path),
        hosts=_host_profiles(settings.get("hosts"), path),
    )


def _host_profiles(value: object, path: Path) -> Mapping[str, HostProfile]:
    if value is None:
        return {}
    hosts = _mapping(value, f"configuration hosts must be a table: {path}")
    profiles: dict[str, HostProfile] = {}
    for name, host_value in hosts.items():
        settings = _mapping(host_value, f"host profile must be a table: {path}")
        unknown = sorted(set(settings) - _HOST_KEYS)
        if unknown:
            raise ConfigurationError(f"unknown host key in {path}: {unknown[0]}")
        profiles[name] = HostProfile(
            sudo=_bool_setting(settings, "sudo", path),
            docker_context=_string_setting(settings, "docker_context", path),
        )
    return profiles


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ConfigurationError(message)
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ConfigurationError(message)
        result[key] = item
    return result


def _string_setting(
    settings: Mapping[str, object], key: str, path: Path
) -> str | None:
    value = settings.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationError(f"configuration key {key!r} must be a string: {path}")
    return value


def _bool_setting(settings: Mapping[str, object], key: str, path: Path) -> bool | None:
    value = settings.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ConfigurationError(f"configuration key {key!r} must be a boolean: {path}")
    return value


def _path_setting(
    settings: Mapping[str, object], key: str, root: Path, path: Path
) -> Path | None:
    value = _string_setting(settings, key, path)
    if value is None:
        return None
    return _resolve_path(value, root)


def _resolve_path(value: str, root: Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return root / path
