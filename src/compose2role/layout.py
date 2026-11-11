"""Discover the Ansible repository layout."""

from __future__ import annotations

import configparser
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from compose2role.config import HostProfile, RepositoryConfig, find_file_upwards
from compose2role.errors import ConfigurationError


@dataclass(frozen=True)
class AnsibleConfig:
    """The documented subset of `ansible.cfg` used by the tool."""

    path: Path
    roles_path: tuple[Path, ...] = ()
    collections_path: tuple[Path, ...] = ()
    inventory: tuple[Path, ...] = ()


@dataclass(frozen=True)
class AnsibleLayout:
    """Repository paths derived from configuration and Ansible conventions."""

    root: Path
    config: RepositoryConfig
    ansible_config: AnsibleConfig | None
    roles_directory: Path
    inventory: tuple[Path, ...]
    collections_path: tuple[Path, ...]
    sops_config: Path | None
    secret_policy: Path | None
    host: HostProfile


def find_ansible_config(start: Path | None = None) -> Path | None:
    """Find the nearest `ansible.cfg` walking up from START."""
    return find_file_upwards(start, "ansible.cfg")


def load_ansible_config(path: Path) -> AnsibleConfig:
    """Read only `[defaults]` `roles_path`, `collections_path`, and `inventory`."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open(encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, UnicodeDecodeError, configparser.Error) as error:
        raise ConfigurationError(f"Ansible configuration is unreadable: {path}") from error

    if not parser.has_section("defaults"):
        return AnsibleConfig(path=path)
    return AnsibleConfig(
        path=path,
        roles_path=_split_config_paths(
            parser.get("defaults", "roles_path", fallback=""), path.parent
        ),
        collections_path=_split_config_paths(
            parser.get("defaults", "collections_path", fallback=""), path.parent
        ),
        inventory=_split_config_paths(
            parser.get("defaults", "inventory", fallback=""), path.parent
        ),
    )


def discover_layout(
    config: RepositoryConfig,
    *,
    start: Path | None = None,
    explicit_output: Path | None = None,
    explicit_sops_config: Path | None = None,
    explicit_secret_policy: Path | None = None,
    host: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> AnsibleLayout:
    """Resolve repository paths with flags first, then environment, then config."""
    environment = os.environ if environ is None else environ
    root = config.root
    anchor = (start if start is not None else root).expanduser().resolve()
    ansible_path = find_ansible_config(anchor)
    ansible_config = load_ansible_config(ansible_path) if ansible_path is not None else None

    roles_directory = (
        _selected_path(explicit_output, environment, None, anchor)
        or config.output
        or (ansible_config.roles_path[0] if ansible_config and ansible_config.roles_path else None)
        or _first_existing((root / "ansible" / "roles", root / "roles"))
        or root / "roles"
    )
    sops_config = (
        _selected_path(explicit_sops_config, environment, None, anchor)
        or _selected_path(None, environment, "COMPOSE2ROLE_SOPS_CONFIG", anchor)
        or config.sops_config
    )
    secret_policy = (
        _selected_path(explicit_secret_policy, environment, None, anchor)
        or _selected_path(None, environment, "COMPOSE2ROLE_SECRET_POLICY", anchor)
        or config.secret_policy
    )

    if ansible_config is not None and ansible_config.inventory:
        inventory = ansible_config.inventory
    else:
        discovered_inventory = _first_existing(
            (root / "inventory", root / "ansible" / "inventory")
        )
        inventory = () if discovered_inventory is None else (discovered_inventory,)

    return AnsibleLayout(
        root=root,
        config=config,
        ansible_config=ansible_config,
        roles_directory=roles_directory,
        inventory=inventory,
        collections_path=ansible_config.collections_path if ansible_config else (),
        sops_config=sops_config,
        secret_policy=secret_policy,
        host=config.host(host),
    )


def _selected_path(
    explicit: Path | None,
    environment: Mapping[str, str],
    environment_name: str | None,
    base: Path,
) -> Path | None:
    if explicit is not None:
        path = explicit.expanduser()
        return path if path.is_absolute() else base / path
    if environment_name is None:
        return None
    value = environment.get(environment_name)
    if not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def _first_existing(candidates: tuple[Path, ...]) -> Path | None:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _split_config_paths(value: str, base: Path) -> tuple[Path, ...]:
    paths: list[Path] = []
    for entry in value.replace(",", os.pathsep).split(os.pathsep):
        entry = entry.strip()
        if not entry:
            continue
        path = Path(entry).expanduser()
        paths.append(path.resolve() if path.is_absolute() else (base / path).resolve())
    return tuple(paths)
