"""Doctor diagnostics at the command-line seam."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from compose2role import doctor as doctor_module
from compose2role.cli import main

_SOPS_STUB = """\
#!/bin/sh
printf 'sops 3.9.0\\n'
exit 0
"""

_GPG_STUB = """\
#!/bin/sh
exit 0
"""

_GALAXY_STUB = """\
#!/bin/sh
if [ "$*" = "collection list --format json" ]; then
  printf '%s' '{"collections": {'
  printf '%s' '"community.docker": {"version": "5.4.0"}, '
  printf '%s' '"community.sops": {"version": "2.5.0"}}}'
  exit 0
fi
exit 1
"""

_EMPTY_STUB = """\
#!/bin/sh
exit 0
"""

_SSH_STUB = """\
#!/bin/sh
if [ -n "${DOCTOR_SSH_LOG:-}" ]; then
  printf '%s\\n' "$*" >> "$DOCTOR_SSH_LOG"
fi
case "$*" in
  -G*)
    printf 'hostname web1\\nuser operator\\nport 2222\\n'
    exit 0
    ;;
  *" info --format "*)
    printf '%s\\n' "${DOCTOR_DOCKER_INFO:-\"\"}"
    exit "${DOCTOR_DOCKER_INFO_STATUS:-0}"
    ;;
  *"compose ls --all --format json"*)
    printf '%s\\n' "${DOCTOR_COMPOSE_LS:-[]}"
    exit 0
    ;;
  *"compose version"*)
    printf 'Docker Compose version %s\\n' "${DOCTOR_COMPOSE_VERSION:-v2.30.0}"
    exit 0
    ;;
esac
exit 1
"""

_SOPS_CONFIG = """\
creation_rules:
  - path_regex: vars/secrets\\.sops\\.yml$
"""


def _install(bin_directory: Path, name: str, script: str) -> Path:
    executable = bin_directory / name
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _install_ansible_tools(bin_directory: Path) -> None:
    _install(bin_directory, "ansible-galaxy", _GALAXY_STUB)
    _install(bin_directory, "ansible-lint", _EMPTY_STUB)
    _install(bin_directory, "ansible-playbook", _EMPTY_STUB)


def _isolate(monkeypatch: pytest.MonkeyPatch, bin_directory: Path) -> None:
    monkeypatch.setenv("PATH", str(bin_directory))
    for name in (
        "COMPOSE2ROLE_SSH_BIN",
        "COMPOSE2ROLE_SOPS_BIN",
        "COMPOSE2ROLE_ANSIBLE_BIN",
        "COMPOSE2ROLE_SSH_LOG",
        "DOCTOR_SSH_LOG",
        "DOCTOR_DOCKER_INFO",
        "DOCTOR_DOCKER_INFO_STATUS",
        "DOCTOR_COMPOSE_LS",
        "DOCTOR_COMPOSE_VERSION",
        "ANSIBLE_COLLECTIONS_PATH",
    ):
        monkeypatch.delenv(name, raising=False)


def _set_os_release(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str) -> None:
    path = tmp_path / "os-release"
    path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(doctor_module, "OS_RELEASE_PATH", path)


def _repository(tmp_path: Path, output: str = "roles", extra: str = "") -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".compose2role.toml").write_text(
        f'[defaults]\noutput = "{output}"\n{extra}', encoding="utf-8"
    )
    return repository


def _invoke(arguments: list[str]) -> object:
    return CliRunner().invoke(main, ["doctor", *arguments])


def _checks(result: object) -> dict[str, dict[str, object]]:
    assert getattr(result, "exit_code") in {0, 1}
    payload = json.loads(getattr(result, "output"))
    return {check["name"]: check for check in payload["checks"]}


def test_doctor_local_reports_every_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "roles").mkdir()
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install(bin_directory, "sops", _SOPS_STUB)
    _install(bin_directory, "gpg", _GPG_STUB)
    _install_ansible_tools(bin_directory)
    _isolate(monkeypatch, bin_directory)
    _set_os_release(monkeypatch, tmp_path, "ID=debian\nID_LIKE=debian\n")

    result = _invoke(["--config", str(repository / ".compose2role.toml")])

    assert getattr(result, "exit_code") == 0
    output = getattr(result, "output")
    assert "✓ config:" in output
    assert "✓ layout:" in output
    assert "✓ sops: sops 3.9.0" in output
    assert "✓ ansible collections: found" in output
    assert "0 warnings, 0 errors" in output


def test_doctor_controller_mode_keeps_its_check_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "roles").mkdir()
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install(bin_directory, "sops", _SOPS_STUB)
    _install(bin_directory, "gpg", _GPG_STUB)
    _install_ansible_tools(bin_directory)
    _isolate(monkeypatch, bin_directory)
    _set_os_release(monkeypatch, tmp_path, "ID=debian\n")

    result = _invoke(
        ["--config", str(repository / ".compose2role.toml"), "--format", "json"]
    )

    assert getattr(result, "exit_code") == 0, getattr(result, "output")
    payload = json.loads(getattr(result, "output"))
    assert [check["name"] for check in payload["checks"]] == [
        "config",
        "layout",
        "secret policy",
        "output",
        "sops",
        "gpg",
        "sops rule",
        "ansible-galaxy",
        "ansible collections",
        "ansible-lint",
        "ansible-playbook",
        "roles",
        "drift",
        "backups",
    ]


def test_doctor_host_mode_requires_ssh_and_reports_no_controller_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "roles").mkdir()
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _isolate(monkeypatch, bin_directory)
    _set_os_release(monkeypatch, tmp_path, 'ID="rhel"\nID_LIKE="fedora"\n')

    result = _invoke(
        ["--host", "web1", "--config", str(repository / ".compose2role.toml"), "--format", "json"]
    )

    checks = _checks(result)
    assert getattr(result, "exit_code") == 1
    assert set(checks) == {"ssh"}
    assert checks["ssh"]["status"] == "error"
    assert checks["ssh"]["required"] is True
    assert "sudo dnf install openssh-clients" in checks["ssh"]["hint"]
    assert json.loads(getattr(result, "output"))["summary"]["failed"] is True


def test_doctor_remote_resolves_ssh_and_checks_remote_compose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "roles").mkdir()
    ssh_log = tmp_path / "ssh.log"
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install(bin_directory, "ssh", _SSH_STUB)
    _isolate(monkeypatch, bin_directory)
    monkeypatch.setenv("DOCTOR_SSH_LOG", str(ssh_log))
    _set_os_release(monkeypatch, tmp_path, "ID=debian\n")

    result = _invoke(
        ["--host", "web1", "--config", str(repository / ".compose2role.toml")]
    )

    assert getattr(result, "exit_code") == 0
    output = getattr(result, "output")
    assert "✓ ssh resolution: ssh -G web1 resolved hostname web1, user operator, port 2222" in (
        output
    )
    assert "✓ remote docker:" in output
    assert "✓ remote compose: remote docker compose v2.30.0" in output
    assert "sops" not in output
    invocations = ssh_log.read_text(encoding="utf-8").splitlines()
    assert "-G -- web1" in invocations
    assert "-- web1 docker compose version" in invocations


def _host_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **environment: str
) -> Path:
    """Install the host-mode stubs and return the repository root."""
    repository = _repository(tmp_path)
    (repository / "roles").mkdir()
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install(bin_directory, "ssh", _SSH_STUB)
    _install(bin_directory, "sops", _SOPS_STUB)
    _install(bin_directory, "gpg", _GPG_STUB)
    _install_ansible_tools(bin_directory)
    _isolate(monkeypatch, bin_directory)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    _set_os_release(monkeypatch, tmp_path, "ID=debian\n")
    return repository


def test_doctor_remote_sudo_prefixes_every_remote_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _host_environment(tmp_path, monkeypatch, DOCTOR_SSH_LOG=str(tmp_path / "ssh.log"))

    result = _invoke(
        ["--host", "web1", "--sudo", "--config", str(repository / ".compose2role.toml")]
    )

    assert getattr(result, "exit_code") == 0, getattr(result, "output")
    invocations = (tmp_path / "ssh.log").read_text(encoding="utf-8")
    assert "-- web1 sudo -n docker info" in invocations
    assert "-- web1 sudo -n docker compose version" in invocations


def test_doctor_host_mode_applies_the_docker_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _host_environment(
        tmp_path, monkeypatch, DOCTOR_SSH_LOG=str(tmp_path / "ssh.log")
    )

    result = _invoke(
        [
            "--host",
            "web1",
            "--docker-context",
            "rootless",
            "--config",
            str(repository / ".compose2role.toml"),
        ]
    )

    assert getattr(result, "exit_code") == 0, getattr(result, "output")
    invocations = (tmp_path / "ssh.log").read_text(encoding="utf-8")
    assert "-- web1 docker --context rootless info" in invocations
    assert "-- web1 docker --context rootless compose version" in invocations


def test_doctor_quotes_the_docker_info_format_for_the_remote_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _host_environment(
        tmp_path, monkeypatch, DOCTOR_SSH_LOG=str(tmp_path / "ssh.log")
    )

    result = _invoke(
        ["--host", "web1", "--config", str(repository / ".compose2role.toml")]
    )

    assert getattr(result, "exit_code") == 0, getattr(result, "output")
    invocations = (tmp_path / "ssh.log").read_text(encoding="utf-8")
    assert "-- web1 docker info --format '{{json .}}'" in invocations


def test_doctor_host_mode_reports_only_the_host_check_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _host_environment(tmp_path, monkeypatch)

    result = _invoke(
        ["--host", "web1", "--format", "json", "--config", str(repository / ".compose2role.toml")]
    )

    assert getattr(result, "exit_code") == 0, getattr(result, "output")
    payload = json.loads(getattr(result, "output"))
    assert [check["name"] for check in payload["checks"]] == [
        "ssh",
        "ssh resolution",
        "remote docker",
        "remote compose",
    ]


def test_doctor_host_mode_fails_when_the_daemon_is_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _host_environment(tmp_path, monkeypatch, DOCTOR_DOCKER_INFO_STATUS="1")

    result = _invoke(
        ["--host", "web1", "--format", "json", "--config", str(repository / ".compose2role.toml")]
    )

    checks = _checks(result)
    assert getattr(result, "exit_code") == 1
    assert checks["remote docker"]["status"] == "error"
    assert checks["remote docker"]["required"] is True
    assert "not reachable" in str(checks["remote docker"]["detail"])


def test_doctor_host_mode_reports_the_daemon_mode_and_project_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _host_environment(
        tmp_path,
        monkeypatch,
        DOCTOR_DOCKER_INFO='{"SecurityOptions":["name=rootless"]}',
        DOCTOR_COMPOSE_LS='[{"Name":"one"},{"Name":"two"}]',
    )

    result = _invoke(
        ["--host", "web1", "--format", "json", "--config", str(repository / ".compose2role.toml")]
    )

    check = _checks(result)["remote docker"]
    assert check["status"] == "ok"
    assert "rootless" in str(check["detail"])
    assert "2 visible Compose project(s)" in str(check["detail"])


def test_doctor_host_mode_accepts_compose_v5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _host_environment(tmp_path, monkeypatch, DOCTOR_COMPOSE_VERSION="v5.7.0")

    result = _invoke(
        ["--host", "web1", "--format", "json", "--config", str(repository / ".compose2role.toml")]
    )

    checks = _checks(result)
    assert getattr(result, "exit_code") == 0
    assert checks["remote compose"]["status"] == "ok"
    assert "v5.7.0" in str(checks["remote compose"]["detail"])


def test_doctor_host_mode_rejects_compose_v1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _host_environment(tmp_path, monkeypatch, DOCTOR_COMPOSE_VERSION="v1.29.2")

    result = _invoke(
        ["--host", "web1", "--format", "json", "--config", str(repository / ".compose2role.toml")]
    )

    checks = _checks(result)
    assert getattr(result, "exit_code") == 1
    assert checks["remote compose"]["status"] == "error"
    assert "v1.29.2" in str(checks["remote compose"]["detail"])


def test_doctor_finds_repo_local_collections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "roles").mkdir()
    snapshot = repository / "collections" / "ansible_collections"
    for name in ("community/docker", "community/sops"):
        collection = snapshot / name
        collection.mkdir(parents=True)
        (collection / "galaxy.yml").write_text("namespace: community\n", encoding="utf-8")
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install(
        bin_directory,
        "ansible-galaxy",
        "#!/bin/sh\nif [ \"$*\" = 'collection list --format json' ]; then\n"
        "  printf '%s' '{}'\n  exit 0\nfi\nexit 1\n",
    )
    _install(bin_directory, "ansible-lint", _EMPTY_STUB)
    _install(bin_directory, "ansible-playbook", _EMPTY_STUB)
    _isolate(monkeypatch, bin_directory)
    _set_os_release(monkeypatch, tmp_path, "ID=debian\n")

    result = _invoke(["--config", str(repository / ".compose2role.toml")])

    assert getattr(result, "exit_code") == 0, getattr(result, "output")
    assert "✓ ansible collections: found community.docker, community.sops" in (
        getattr(result, "output")
    )


def test_doctor_honours_the_ansible_collections_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "roles").mkdir()
    external = tmp_path / "external-collections"
    for name in ("community/docker", "community/sops"):
        collection = external / "ansible_collections" / name
        collection.mkdir(parents=True)
        (collection / "galaxy.yml").write_text("namespace: community\n", encoding="utf-8")
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install(
        bin_directory,
        "ansible-galaxy",
        "#!/bin/sh\nif [ \"$*\" = 'collection list --format json' ]; then\n"
        "  printf '%s' '{}'\n  exit 0\nfi\nexit 1\n",
    )
    _install(bin_directory, "ansible-lint", _EMPTY_STUB)
    _install(bin_directory, "ansible-playbook", _EMPTY_STUB)
    _isolate(monkeypatch, bin_directory)
    monkeypatch.setenv("ANSIBLE_COLLECTIONS_PATH", str(external))
    _set_os_release(monkeypatch, tmp_path, "ID=debian\n")

    result = _invoke(["--config", str(repository / ".compose2role.toml")])

    assert getattr(result, "exit_code") == 0, getattr(result, "output")
    assert "✓ ansible collections: found" in getattr(result, "output")


def test_doctor_distro_hints_name_the_package_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "roles").mkdir()
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _isolate(monkeypatch, bin_directory)
    _set_os_release(monkeypatch, tmp_path, 'ID="rocky"\nID_LIKE="rhel centos fedora"\n')

    result = _invoke(["--config", str(repository / ".compose2role.toml")])

    output = getattr(result, "output")
    assert "sudo dnf install sops (EPEL)" in output
    assert "sudo dnf install gnupg2" in output


def test_doctor_reports_configuration_and_secret_policy_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _isolate(monkeypatch, bin_directory)
    _set_os_release(monkeypatch, tmp_path, "ID=debian\n")

    invalid_config = tmp_path / "invalid.toml"
    invalid_config.write_text("this is not = toml", encoding="utf-8")
    config_result = _invoke(["--config", str(invalid_config)])
    assert getattr(config_result, "exit_code") == 2
    assert "✗ config:" in getattr(config_result, "output")

    repository = _repository(tmp_path, extra='secret_policy = "policy.toml"\n')
    (repository / "roles").mkdir()
    (repository / "policy.toml").write_text("rules = 5\n", encoding="utf-8")
    secret_policy_result = _invoke(["--config", str(repository / ".compose2role.toml")])
    assert getattr(secret_policy_result, "exit_code") == 0
    assert "! secret policy: secret policy must define rules" in getattr(
        secret_policy_result, "output"
    )


def test_doctor_reports_an_unwritable_output_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path, output="blocked/roles")
    (repository / "blocked").write_text("not a directory", encoding="utf-8")
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _isolate(monkeypatch, bin_directory)
    _set_os_release(monkeypatch, tmp_path, "ID=debian\n")

    result = _invoke(["--config", str(repository / ".compose2role.toml")])

    assert getattr(result, "exit_code") == 1
    assert "✗ output: roles directory is not writable" in getattr(result, "output")


def test_doctor_validates_a_configured_sops_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "roles").mkdir()
    invalid_config = tmp_path / "invalid-sops.yaml"
    invalid_config.write_text("creation_rules: []\n", encoding="utf-8")
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install(bin_directory, "sops", _SOPS_STUB)
    _isolate(monkeypatch, bin_directory)
    _set_os_release(monkeypatch, tmp_path, "ID=debian\n")

    result = _invoke(
        [
            "--config",
            str(repository / ".compose2role.toml"),
            "--sops-config",
            str(invalid_config),
        ]
    )

    assert getattr(result, "exit_code") == 1
    assert "✗ sops rule:" in getattr(result, "output")


def _write_role(roles_directory: Path, project_root: Path, content: bytes) -> Path:
    project_root.mkdir()
    (project_root / "compose.yaml").write_bytes(content)
    role_directory = roles_directory / "my_app"
    role_directory.mkdir()
    provenance = {
        "files": {
            "compose.yaml": {
                "redacted": False,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        },
        "generator": "compose2role",
        "mode": "local",
        "project": "my-app",
        "role": "my_app",
        "source": {
            "config_files": [str(project_root / "compose.yaml")],
            "root": str(project_root),
        },
        "structural_hash": "fixture",
        "version": "0.1.0",
    }
    (role_directory / ".compose2role.json").write_text(
        json.dumps(provenance), encoding="utf-8"
    )
    return role_directory


def test_doctor_reports_roles_drift_and_backups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    roles_directory = repository / "roles"
    roles_directory.mkdir()
    project_root = tmp_path / "project"
    _write_role(roles_directory, project_root, b"services:\n  web:\n    image: web:1\n")
    backup = roles_directory / ".compose2role" / "backups" / "my_app-20260101T000000Z"
    backup.mkdir(parents=True)
    (backup / "compose.yaml").write_bytes(b"x" * 2048)
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _isolate(monkeypatch, bin_directory)
    _set_os_release(monkeypatch, tmp_path, "ID=debian\n")

    result = _invoke(["--config", str(repository / ".compose2role.toml")])

    assert getattr(result, "exit_code") == 0
    output = getattr(result, "output")
    assert "✓ roles: 1 generated role(s)" in output
    assert "✓ drift: 1 unchanged, 0 source changed, 0 source unavailable" in output
    assert "✓ backups: 1 backup(s), 2.0 KiB" in output
    assert "prune with: rm -r" in output

    (project_root / "compose.yaml").write_bytes(b"services:\n  web:\n    image: web:2\n")
    drifted = _invoke(["--config", str(repository / ".compose2role.toml")])

    assert getattr(drifted, "exit_code") == 0
    assert "! drift: 0 unchanged, 1 source changed, 0 source unavailable" in getattr(
        drifted, "output"
    )
