from __future__ import annotations

import json
import os
from importlib.metadata import version as package_version
from pathlib import Path

import pytest
from click.testing import CliRunner

from compose2role.cli import main


def test_version_reports_the_installed_package_version() -> None:
    result = CliRunner().invoke(main, ["--version"], prog_name="compose2role")

    assert result.exit_code == 0, result.output
    assert result.output == f"compose2role {package_version('compose2role')}\n"


def _install_stub_ssh(tmp_path: Path, script: str) -> Path:
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    ssh = bin_directory / "ssh"
    ssh.write_text(script, encoding="utf-8")
    ssh.chmod(0o755)
    return bin_directory


def _ssh_environment(bin_directory: Path, arguments_file: Path | None = None) -> dict[str, str]:
    environment = {"PATH": f"{bin_directory}:{os.environ['PATH']}"}
    if arguments_file is not None:
        environment["C2R_SSH_ARGUMENTS"] = str(arguments_file)
    return environment


def test_discover_lists_remote_compose_projects_as_json(tmp_path: Path) -> None:
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
printf '%s\\n' '[{"Name":"myapp","Status":"running(1)","ConfigFiles":"/srv/myapp/compose.yaml"}]'
""",
    )

    result = CliRunner().invoke(
        main,
        ["discover", "--host", "web1", "--format", "json"],
        env=_ssh_environment(bin_directory),
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "projects": [
            {
                "config_files": ["/srv/myapp/compose.yaml"],
                "name": "myapp",
                "status": "running(1)",
            }
        ]
    }


def test_discover_prints_one_status_line_per_project(tmp_path: Path) -> None:
    """Text discovery streams a status line per project and closes with a count."""
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}]'
""",
    )

    result = CliRunner().invoke(
        main,
        ["discover", "--host", "web1"],
        env=_ssh_environment(bin_directory),
    )

    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == [
        "Discovering projects on web1...",
        "✓ myapp  running(1)  /srv/myapp/compose.yaml",
        "",
        "1 found",
    ]


@pytest.mark.parametrize(
    ("arguments", "expected_ssh_arguments"),
    (
        (
            ["discover", "--host", "admin@web1.example:2222", "--format", "json"],
            [
                "-p",
                "2222",
                "--",
                "admin@web1.example",
                "docker",
                "compose",
                "ls",
                "--all",
                "--format",
                "json",
            ],
        ),
        (
            [
                "discover",
                "--host",
                "admin@web1.example:2222",
                "--sudo",
                "--format",
                "json",
            ],
            [
                "-p",
                "2222",
                "--",
                "admin@web1.example",
                "sudo",
                "-n",
                "docker",
                "compose",
                "ls",
                "--all",
                "--format",
                "json",
            ],
        ),
    ),
)
def test_discover_passes_fixed_ssh_arguments(
    tmp_path: Path, arguments: list[str], expected_ssh_arguments: list[str]
) -> None:
    arguments_file = tmp_path / "ssh-arguments"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
printf '%s\\n' "$@" > "$C2R_SSH_ARGUMENTS"
printf '%s\\n' '[]'
""",
    )

    result = CliRunner().invoke(
        main,
        arguments,
        env=_ssh_environment(bin_directory, arguments_file),
    )

    assert result.exit_code == 0, result.output
    assert arguments_file.read_text(encoding="utf-8").splitlines() == expected_ssh_arguments


@pytest.mark.parametrize(
    ("arguments", "expected_message"),
    (
        (
            ["discover", "--host", "web1", "--sudo"],
            "ensure the SSH user has passwordless sudo access to Docker",
        ),
        (
            ["discover", "--host", "web1"],
            "join the docker group",
        ),
    ),
)
def test_discover_explains_remote_docker_access_failures(
    tmp_path: Path, arguments: list[str], expected_message: str
) -> None:
    bin_directory = _install_stub_ssh(tmp_path, "#!/bin/sh\nexit 1\n")

    result = CliRunner().invoke(
        main,
        arguments,
        env=_ssh_environment(bin_directory),
    )

    assert result.exit_code == 1
    assert expected_message in result.output


def test_discover_enumerates_the_access_remedies_without_recommending_one(
    tmp_path: Path,
) -> None:
    bin_directory = _install_stub_ssh(tmp_path, "#!/bin/sh\nexit 1\n")

    result = CliRunner().invoke(
        main,
        ["discover", "--host", "web1"],
        env=_ssh_environment(bin_directory),
    )

    assert result.exit_code == 1
    assert "join the docker group" in result.output
    assert "configure passwordless sudo" in result.output
    assert "--docker-context" in result.output
    assert "--sudo" not in result.output


def test_discover_reports_ssh_connection_failures_without_a_sudo_hint(tmp_path: Path) -> None:
    bin_directory = _install_stub_ssh(
        tmp_path,
        "#!/bin/sh\nprintf '%s\\n' 'Host key verification failed.' >&2\nexit 255\n",
    )

    result = CliRunner().invoke(
        main,
        ["discover", "--host", "web1", "--sudo"],
        env=_ssh_environment(bin_directory),
    )

    assert result.exit_code == 1
    assert "SSH connection or remote command failed" in result.output
    assert "Host key verification failed." in result.output
    assert "passwordless sudo" not in result.output
