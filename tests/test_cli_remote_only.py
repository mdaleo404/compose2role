from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from compose2role.cli import main


@pytest.mark.parametrize("command", ("generate", "audit"))
def test_local_invocation_exits_with_a_usage_error(command: str) -> None:
    result = CliRunner().invoke(main, [command])

    assert result.exit_code == 2
    assert "was removed" in result.output
    assert "--host" in result.output


@pytest.mark.parametrize("command", ("generate", "audit"))
def test_local_source_is_rejected(command: str, tmp_path: Path) -> None:
    source = tmp_path / "compose.yaml"
    source.write_text("services: {}\n", encoding="utf-8")

    result = CliRunner().invoke(main, [command, str(source)])

    assert result.exit_code == 2
    assert "Got unexpected extra argument" in result.output


@pytest.mark.parametrize("command", ("generate", "audit"))
def test_help_lists_only_remote_options(command: str) -> None:
    result = CliRunner().invoke(main, [command, "--help"])

    assert result.exit_code == 0
    for option in (
        "--file",
        "--project-dir",
        "--env-file",
        "--resolve-with",
        "--name",
        "--sops-pgp",
    ):
        assert option not in result.output


@pytest.mark.parametrize(
    "arguments",
    (
        ("--playbook",),
        ("--playbook-dir", "playbooks"),
    ),
)
def test_generate_no_longer_offers_playbook_options(arguments: tuple[str, ...]) -> None:
    result = CliRunner().invoke(
        main, ["generate", "--host", "web1", "--project", "my-app", *arguments]
    )

    assert result.exit_code == 2
    assert "No such option" in result.output
