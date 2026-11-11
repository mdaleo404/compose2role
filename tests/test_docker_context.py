"""Docker context selection at the command-line and generated-role seams."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from ruamel.yaml import YAML
from ssh_stub import legacy_source_session_bridge

from compose2role.cli import main

_SOURCE_DOCUMENT = """\
services:
  web:
    image: "web:1"
"""

_CANONICAL_DOCUMENT = {"services": {"web": {"image": "web:1"}}}

_SOPS_CONFIG = """\
creation_rules:
  - path_regex: vars/secrets\\.sops\\.yml$
"""

_SSH_STUB = """\
#!/bin/sh
request=$(cat)

if [ -n "${C2R_SSH_LOG:-}" ]; then
  printf '%s\\n' "$*" >> "$C2R_SSH_LOG"
  case "$request" in
    *"docker --context rootless compose --project-name"*)
      printf 'canonicalized\\n' >> "$C2R_SSH_LOG"
      ;;
  esac
fi

case "$*" in
  *"compose ls --all --format json"*)
    printf '[{"Name":"my-app","Status":"running(1)","ConfigFiles":"/srv/my-app/compose.yaml"}]\\n'
    exit 0
    ;;
  *" ps --all --format "*)
    printf '%s' "${C2R_WORKING_DIRECTORY_LABEL:-}"
    exit 0
    ;;
esac

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s\\n' 'file 640 0 0'
    printf '%s\\n' "$C2R_SOURCE_DOCUMENT"
    ;;
  stat)
    printf '%s\\n' missing
    ;;
  config)
    printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
    ;;
  *)
    exit 97
    ;;
esac
"""


def _install(bin_directory: Path, name: str, script: str) -> Path:
    executable = bin_directory / name
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, hosts: str = ""
) -> tuple[Path, Path]:
    """Return the repository and SSH log for one isolated run."""
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    legacy_ssh = _install(bin_directory, "ssh-legacy", _SSH_STUB)
    _install(bin_directory, "ssh", legacy_source_session_bridge(legacy_ssh))
    _install(bin_directory, "sops", "#!/bin/sh\nexit 99\n")
    monkeypatch.setenv("PATH", f"{bin_directory}:{os.environ['PATH']}")
    ssh_log = tmp_path / "ssh.log"
    monkeypatch.setenv("C2R_SSH_LOG", str(ssh_log))
    monkeypatch.setenv(
        "C2R_SOURCE_DOCUMENT",
        base64.b64encode(_SOURCE_DOCUMENT.encode("utf-8")).decode("ascii"),
    )
    monkeypatch.setenv("C2R_CANONICAL_DOCUMENT", json.dumps(_CANONICAL_DOCUMENT))
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(_SOPS_CONFIG, encoding="utf-8")
    monkeypatch.setenv("COMPOSE2ROLE_SOPS_CONFIG", str(sops_config))
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".compose2role.toml").write_text(
        f'[defaults]\noutput = "roles"\n\n{hosts}', encoding="utf-8"
    )
    return repository, ssh_log


def _lines(ssh_log: Path) -> list[str]:
    if not ssh_log.exists():
        return []
    return ssh_log.read_text(encoding="utf-8").splitlines()


def test_discover_passes_the_context_to_the_discovery_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, ssh_log = _environment(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        main,
        [
            "discover",
            "--host",
            "web1",
            "--docker-context",
            "rootless",
            "--config",
            str(repository / ".compose2role.toml"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "-- web1 docker --context rootless compose ls --all --format json" in _lines(
        ssh_log
    )


def test_discover_without_a_context_keeps_the_plain_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, ssh_log = _environment(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        main,
        ["discover", "--host", "web1", "--config", str(repository / ".compose2role.toml")],
    )

    assert result.exit_code == 0, result.output
    assert "-- web1 docker compose ls --all --format json" in _lines(ssh_log)


def test_the_configured_context_applies_when_the_flag_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, ssh_log = _environment(
        tmp_path, monkeypatch, hosts='[hosts."web1"]\ndocker_context = "rootless"\n'
    )

    result = CliRunner().invoke(
        main,
        ["discover", "--host", "web1", "--config", str(repository / ".compose2role.toml")],
    )

    assert result.exit_code == 0, result.output
    assert "-- web1 docker --context rootless compose ls --all --format json" in _lines(
        ssh_log
    )


def test_the_flag_wins_over_the_configured_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, ssh_log = _environment(
        tmp_path, monkeypatch, hosts='[hosts."web1"]\ndocker_context = "production"\n'
    )

    result = CliRunner().invoke(
        main,
        [
            "discover",
            "--host",
            "web1",
            "--docker-context",
            "rootless",
            "--config",
            str(repository / ".compose2role.toml"),
        ],
    )

    assert result.exit_code == 0, result.output
    lines = _lines(ssh_log)
    assert "-- web1 docker --context rootless compose ls --all --format json" in lines
    assert not any("production" in line for line in lines)


def test_audit_uses_the_context_for_the_working_directory_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, ssh_log = _environment(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        main,
        [
            "audit",
            "--host",
            "web1",
            "--all",
            "--docker-context",
            "rootless",
            "--config",
            str(repository / ".compose2role.toml"),
        ],
    )

    assert result.exit_code == 0, result.output
    lines = _lines(ssh_log)
    assert "-- web1 docker --context rootless compose ls --all --format json" in lines
    assert any("docker --context rootless ps --all --format " in line for line in lines)


def test_generate_uses_the_context_for_discovery_and_canonicalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, ssh_log = _environment(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--docker-context",
            "rootless",
            "--config",
            str(repository / ".compose2role.toml"),
        ],
    )

    assert result.exit_code == 0, result.output
    lines = _lines(ssh_log)
    assert "-- web1 docker --context rootless compose ls --all --format json" in lines
    assert "canonicalized" in lines


def test_generate_without_a_context_uses_the_plain_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, ssh_log = _environment(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--config",
            str(repository / ".compose2role.toml"),
        ],
    )

    assert result.exit_code == 0, result.output
    lines = _lines(ssh_log)
    assert "-- web1 docker compose ls --all --format json" in lines
    assert "canonicalized" not in lines


@pytest.mark.parametrize(
    "arguments",
    (
        ("discover", "--host", "web1"),
        ("audit", "--host", "web1", "--all"),
        ("generate", "--host", "web1", "--project", "my-app"),
        ("doctor", "--host", "web1"),
    ),
)
def test_an_invalid_context_name_is_a_usage_error_before_ssh(
    arguments: tuple[str, ...], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, ssh_log = _environment(tmp_path, monkeypatch)

    result = CliRunner().invoke(
        main,
        [
            *arguments,
            "--docker-context",
            "not a context",
            "--config",
            str(repository / ".compose2role.toml"),
        ],
    )

    assert result.exit_code == 2, result.output
    assert "not a context" in result.output
    assert _lines(ssh_log) == []


def _generate(tmp_path: Path, repository: Path, output: str, *extra: str) -> object:
    return CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(tmp_path / output),
            "--config",
            str(repository / ".compose2role.toml"),
            *extra,
        ],
    )


def test_a_generation_records_the_context_in_the_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ssh_log = _environment(tmp_path, monkeypatch)

    result = _generate(tmp_path, repository, "context-roles", "--docker-context", "rootless")

    assert result.exit_code == 0, result.output
    role = tmp_path / "context-roles" / "my_app"
    defaults = YAML(typ="safe").load(
        (role / "defaults" / "main.yml").read_text(encoding="utf-8")
    )
    tasks = YAML(typ="safe").load(
        (role / "tasks" / "main.yml").read_text(encoding="utf-8")
    )
    assert defaults["my_app_docker_context"] == "rootless"
    compose = next(task for task in tasks if task["name"] == "Deploy my_app Compose project")
    assert compose["community.docker.docker_compose_v2"]["cli_context"] == (
        "{{ my_app_docker_context }}"
    )
    assert "docker_context" not in (role / ".compose2role.json").read_text(encoding="utf-8")


def test_a_context_free_generation_leaves_every_other_file_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ssh_log = _environment(tmp_path, monkeypatch)
    plain = _generate(tmp_path, repository, "plain-roles")
    contextual = _generate(
        tmp_path, repository, "context-roles", "--docker-context", "rootless"
    )
    assert plain.exit_code == 0, plain.output
    assert contextual.exit_code == 0, contextual.output

    plain_role = tmp_path / "plain-roles" / "my_app"
    context_role = tmp_path / "context-roles" / "my_app"
    plain_defaults = (plain_role / "defaults" / "main.yml").read_text(encoding="utf-8")
    plain_tasks = (plain_role / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert plain_defaults == (
        "---\n"
        'my_app_project_dir: "/srv/my-app"\n'
        'my_app_compose_project_name: "my-app"\n'
        'my_app_web_image: "web"\n'
        'my_app_web_image_tag: "1"\n'
    )
    assert "docker_context" not in plain_defaults
    assert "cli_context" not in plain_tasks

    plain_files = {
        path.relative_to(plain_role): path.read_bytes()
        for path in plain_role.rglob("*")
        if path.is_file()
    }
    context_files = {
        path.relative_to(context_role): path.read_bytes()
        for path in context_role.rglob("*")
        if path.is_file()
    }
    assert set(plain_files) == set(context_files)
    for relative, content in plain_files.items():
        if str(relative) in {"defaults/main.yml", "tasks/main.yml"}:
            assert context_files[relative] != content
            continue
        assert context_files[relative] == content, relative
