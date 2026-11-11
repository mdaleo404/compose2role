from __future__ import annotations

from pathlib import Path

import pytest

from compose2role.config import (
    HostProfile,
    find_repository_config,
    load_repository_config,
)
from compose2role.errors import ConfigurationError


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_explicit_config_wins_over_environment_and_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    _write(repository / ".compose2role.toml", "[defaults]\noutput = 'discovered'\n")
    environment_config = _write(
        tmp_path / "environment.toml", "[defaults]\noutput = 'environment'\n"
    )
    explicit_config = _write(tmp_path / "explicit.toml", "[defaults]\noutput = 'explicit'\n")
    monkeypatch.setenv("COMPOSE2ROLE_CONFIG", str(environment_config))

    config = load_repository_config(explicit_config, start=repository)

    assert config.path == explicit_config
    assert config.output == explicit_config.parent / "explicit"


def test_environment_config_wins_over_discovered_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    _write(repository / ".compose2role.toml", "[defaults]\noutput = 'discovered'\n")
    environment_config = _write(
        tmp_path / "environment.toml", "[defaults]\noutput = 'environment'\n"
    )
    monkeypatch.setenv("COMPOSE2ROLE_CONFIG", str(environment_config))

    config = load_repository_config(start=repository)

    assert config.path == environment_config
    assert config.output == environment_config.parent / "environment"


def test_nearest_compose2role_config_is_discovered_walking_up(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    discovered = _write(
        repository / ".compose2role.toml", "[defaults]\noutput = 'ansible/roles'\n"
    )
    nested = repository / "stacks" / "web"

    config = load_repository_config(start=nested, environ={})

    assert config.path == discovered
    assert config.output == repository / "ansible" / "roles"


def test_ansible_cfg_is_the_fallback_configuration_root(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    ansible_config = _write(repository / "ansible.cfg", "[defaults]\n")
    nested = repository / "stacks" / "web"

    config = load_repository_config(start=nested, environ={})

    assert config.path == ansible_config
    assert config.root == repository


def test_compose2role_config_beats_a_closer_ansible_cfg(tmp_path: Path) -> None:
    _write(tmp_path / "ansible.cfg", "[defaults]\n")
    discovered = _write(tmp_path / "stacks" / ".compose2role.toml", "[defaults]\n")

    assert find_repository_config(tmp_path / "stacks" / "web") == discovered


def test_defaults_and_host_profiles_are_parsed(tmp_path: Path) -> None:
    config_path = _write(
        tmp_path / ".compose2role.toml",
        """\
[defaults]
output = "ansible/roles"
sops_config = "ansible/.sops.yaml"
secret_policy = "ansible/policy.toml"

[hosts.web1]
sudo = true
docker_context = "rootless"
""",
    )

    config = load_repository_config(config_path, environ={})

    assert config.output == tmp_path / "ansible" / "roles"
    assert config.sops_config == tmp_path / "ansible" / ".sops.yaml"
    assert config.secret_policy == tmp_path / "ansible" / "policy.toml"
    assert config.host("web1") == HostProfile(sudo=True, docker_context="rootless")
    assert config.host("unknown") == HostProfile()


def test_host_docker_context_is_parsed(tmp_path: Path) -> None:
    config_path = _write(
        tmp_path / ".compose2role.toml",
        '[hosts."web1"]\ndocker_context = "rootless"\n',
    )

    config = load_repository_config(config_path, environ={})

    assert config.host("web1").docker_context == "rootless"
    assert config.host("web1").sudo is None


@pytest.mark.parametrize(
    "content",
    (
        "[defaults\n",
        "[unknown]\nvalue = true\n",
        "[defaults]\nbogus = true\n",
        "[defaults]\nplaybook = 'yes'\n",
        "[defaults]\nplaybook = true\n",
        "[defaults]\nplaybook_dir = 'playbooks'\n",
        "[defaults]\noutput = 1\n",
        "[hosts.web1]\nbogus = true\n",
        "[hosts.web1]\nsudo = 'yes'\n",
        "[hosts.web1]\ndocker_context = 5\n",
    ),
)
def test_invalid_configuration_is_a_configuration_error(tmp_path: Path, content: str) -> None:
    config_path = _write(tmp_path / ".compose2role.toml", content)

    with pytest.raises(ConfigurationError):
        load_repository_config(config_path, environ={})


def test_missing_explicit_configuration_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_repository_config(tmp_path / "missing.toml", environ={})
