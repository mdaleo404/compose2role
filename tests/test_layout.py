from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from compose2role.cli import main
from compose2role.config import RepositoryConfig, load_repository_config
from compose2role.layout import discover_layout, find_ansible_config, load_ansible_config
from compose2role.naming import normalize_compose_project_name, normalize_role_name


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _config(tmp_path: Path, content: str) -> RepositoryConfig:
    return load_repository_config(_write(tmp_path / ".compose2role.toml", content), environ={})


def test_roles_directory_prefers_explicit_output(tmp_path: Path) -> None:
    layout = discover_layout(
        RepositoryConfig(root=tmp_path),
        start=tmp_path,
        explicit_output=tmp_path / "explicit",
        environ={},
    )

    assert layout.roles_directory == tmp_path / "explicit"


def test_roles_directory_uses_config_defaults_before_ansible_cfg(tmp_path: Path) -> None:
    _write(tmp_path / "ansible.cfg", "[defaults]\nroles_path = ansible/roles\n")
    config = _config(tmp_path, "[defaults]\noutput = 'configured/roles'\n")

    layout = discover_layout(config, start=tmp_path, environ={})

    assert layout.roles_directory == tmp_path / "configured" / "roles"


def test_roles_directory_uses_the_first_ansible_cfg_roles_path_entry(tmp_path: Path) -> None:
    _write(
        tmp_path / "ansible.cfg",
        "[defaults]\nroles_path = ansible/roles:extra/roles\n",
    )

    layout = discover_layout(RepositoryConfig(root=tmp_path), start=tmp_path, environ={})

    assert layout.roles_directory == tmp_path / "ansible" / "roles"


def test_roles_directory_falls_back_to_existing_ansible_roles(tmp_path: Path) -> None:
    (tmp_path / "ansible" / "roles").mkdir(parents=True)

    layout = discover_layout(RepositoryConfig(root=tmp_path), start=tmp_path, environ={})

    assert layout.roles_directory == tmp_path / "ansible" / "roles"


def test_roles_directory_falls_back_to_existing_roles(tmp_path: Path) -> None:
    (tmp_path / "roles").mkdir()

    layout = discover_layout(RepositoryConfig(root=tmp_path), start=tmp_path, environ={})

    assert layout.roles_directory == tmp_path / "roles"


def test_roles_directory_falls_back_to_config_root_roles(tmp_path: Path) -> None:
    layout = discover_layout(RepositoryConfig(root=tmp_path), start=tmp_path, environ={})

    assert layout.roles_directory == tmp_path / "roles"


def test_ansible_cfg_only_reads_the_documented_defaults_keys(tmp_path: Path) -> None:
    _write(
        tmp_path / "ansible.cfg",
        """\
[defaults]
roles_path = documented/roles
unknown = ignored

[other]
roles_path = ignored/roles
""",
    )

    layout = discover_layout(RepositoryConfig(root=tmp_path), start=tmp_path, environ={})

    assert layout.roles_directory == tmp_path / "documented" / "roles"


def test_ansible_cfg_paths_resolve_relative_to_the_config_file(tmp_path: Path) -> None:
    ansible_config = _write(
        tmp_path / "ansible.cfg",
        """\
[defaults]
roles_path = roles
collections_path = collections:more-collections
inventory = inventory/hosts.ini:inventory/extra.ini
""",
    )

    parsed = load_ansible_config(ansible_config)

    assert parsed.roles_path == (tmp_path / "roles",)
    assert parsed.collections_path == (tmp_path / "collections", tmp_path / "more-collections")
    assert parsed.inventory == (
        tmp_path / "inventory" / "hosts.ini",
        tmp_path / "inventory" / "extra.ini",
    )


def test_inventory_directory_is_discovered_without_ansible_cfg(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory"
    inventory.mkdir()

    layout = discover_layout(RepositoryConfig(root=tmp_path), start=tmp_path, environ={})

    assert layout.inventory == (inventory,)


def test_find_ansible_config_walks_up(tmp_path: Path) -> None:
    ansible_config = _write(tmp_path / "ansible.cfg", "[defaults]\n")
    nested = tmp_path / "stacks" / "web"

    assert find_ansible_config(nested) == ansible_config


def test_sops_config_precedence(tmp_path: Path) -> None:
    config = RepositoryConfig(root=tmp_path, sops_config=tmp_path / "configured.yaml")

    explicit = discover_layout(
        config,
        start=tmp_path,
        explicit_sops_config=tmp_path / "explicit.yaml",
        environ={},
    )
    environment = discover_layout(
        config,
        start=tmp_path,
        environ={"COMPOSE2ROLE_SOPS_CONFIG": str(tmp_path / "environment.yaml")},
    )
    configured = discover_layout(config, start=tmp_path, environ={})

    assert explicit.sops_config == tmp_path / "explicit.yaml"
    assert environment.sops_config == tmp_path / "environment.yaml"
    assert configured.sops_config == tmp_path / "configured.yaml"


def test_secret_policy_precedence(tmp_path: Path) -> None:
    config = RepositoryConfig(root=tmp_path, secret_policy=tmp_path / "configured.toml")

    explicit = discover_layout(
        config,
        start=tmp_path,
        explicit_secret_policy=tmp_path / "explicit.toml",
        environ={},
    )
    environment = discover_layout(
        config,
        start=tmp_path,
        environ={"COMPOSE2ROLE_SECRET_POLICY": str(tmp_path / "environment.toml")},
    )
    configured = discover_layout(config, start=tmp_path, environ={})

    assert explicit.secret_policy == tmp_path / "explicit.toml"
    assert environment.secret_policy == tmp_path / "environment.toml"
    assert configured.secret_policy == tmp_path / "configured.toml"


def test_host_profile_is_selected_for_the_target_host(tmp_path: Path) -> None:
    config = _config(tmp_path, "[hosts.web1]\nsudo = true\n")

    layout = discover_layout(config, start=tmp_path, host="web1", environ={})
    other = discover_layout(config, start=tmp_path, host="web2", environ={})

    assert layout.host.sudo is True
    assert other.host.sudo is None


def test_normalizers_produce_valid_names() -> None:
    assert normalize_role_name("My App") == "my_app"
    assert normalize_role_name("123") == "compose_123"
    assert normalize_compose_project_name("My App") == "myapp"
    assert normalize_compose_project_name("---") == "compose"


def test_invalid_configuration_exits_with_usage_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path / ".compose2role.toml", "[defaults\n")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["discover", "--host", "web1"])

    assert result.exit_code == 2, result.output
    assert "configuration" in result.output.lower()
