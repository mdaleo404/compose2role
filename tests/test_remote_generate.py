"""Remote generation behavior at the command-line and emitted-role seams."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner
from jinja2 import Environment
from ruamel.yaml import YAML
from ssh_stub import legacy_source_session_bridge

from compose2role.cli import main


def _install_stub_command(bin_directory: Path, name: str, script: str) -> None:
    command = bin_directory / name
    if name == "ssh":
        legacy_ssh = bin_directory / "ssh-legacy"
        legacy_ssh.write_text(script, encoding="utf-8")
        legacy_ssh.chmod(0o755)
        command.write_text(legacy_source_session_bridge(legacy_ssh), encoding="utf-8")
        command.chmod(0o755)
        return
    command.write_text(script, encoding="utf-8")
    command.chmod(0o755)


def _encrypted_sops_output(*keys: str) -> str:
    return "\n".join(
        (
            *(f"{key}: ENC[AES256_GCM,data:fixture]" for key in keys),
            "sops:",
            "  mac: ENC[AES256_GCM,data:fixture]",
        )
    )


def _ansible_executable(name: str) -> str:
    configured_bin = os.environ.get("COMPOSE2ROLE_ANSIBLE_BIN")
    return str(Path(configured_bin) / name) if configured_bin else name


def _assert_generated_role_validates(
    tmp_path: Path, output_directory: Path, role_name: str
) -> None:
    """Lint and syntax-check one generated role against the pinned collections."""
    role_directory = output_directory / role_name
    environment = {
        **os.environ,
        "ANSIBLE_COLLECTIONS_PATH": str(Path(__file__).parents[1] / "collections"),
        "ANSIBLE_ROLES_PATH": str(output_directory),
    }
    lint_result = subprocess.run(
        [
            _ansible_executable("ansible-lint"),
            "--exclude",
            str(role_directory / "vars" / "secrets.sops.yml"),
            str(role_directory),
        ],
        check=False,
        capture_output=True,
        # ansible-lint treats the working directory as the project and skips an
        # out-of-tree target, so lint from the roles directory, not the repository.
        cwd=output_directory,
        env=environment,
        text=True,
    )
    assert lint_result.returncode == 0, lint_result.stdout + lint_result.stderr
    playbook = tmp_path / "syntax-check.yml"
    playbook.write_text(
        f"""\
---
- name: Validate generated role syntax
  hosts: localhost
  connection: local
  gather_facts: false
  roles:
    - {role_name}
""",
        encoding="utf-8",
    )
    syntax_result = subprocess.run(
        [
            _ansible_executable("ansible-playbook"),
            "--inventory",
            "localhost,",
            "--connection",
            "local",
            "--syntax-check",
            str(playbook),
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    assert syntax_result.returncode == 0, syntax_result.stdout + syntax_result.stderr


def _remote_environment(
    tmp_path: Path, source_document: str, canonical_document: dict[str, object]
) -> tuple[dict[str, str], Path]:
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  config_path=${C2R_CONFIG_PATH:-/srv/my-app/compose.yaml}
  printf '[{"Name":"my-app","Status":"running(1)","ConfigFiles":"%s"}]\\n' "$config_path"
  exit 0
fi

case "$*" in
  *"docker ps"*)
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
""",
    )
    _install_stub_command(bin_directory, "sops", "#!/bin/sh\nexit 99\n")
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    return (
        {
            "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
            "C2R_SOURCE_DOCUMENT": base64.b64encode(source_document.encode("utf-8")).decode(
                "ascii"
            ),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
        sops_config,
    )


def test_generate_creates_a_secret_free_remote_role(tmp_path: Path) -> None:
    """A source-fidelity role adopts one remote Compose file in place."""
    source_document = (
        "# Preserve comments, quotes, ordering, and CRLF.\r\n"
        "services:\r\n"
        "  web:\r\n"
        "    image: \"ghcr.io/example/web:1.2.3\"\r\n"
        "    ports:\r\n"
        "      - \"8080:80\"\r\n"
        "    environment:\r\n"
        "      LOG_LEVEL: info\r\n"
    )
    canonical_document = {
        "services": {
            "web": {
                "environment": {"LOG_LEVEL": "info"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "ports": [{"target": 80, "published": "8080", "protocol": "tcp"}],
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == [
        "Discovering projects on web1...",
        "✓ my-app -> my_app (generated)",
        "",
        "1 generated",
    ]
    role_directory = output_directory / "my_app"
    defaults = (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert 'my_app_compose_project_name: "my-app"' in defaults
    assert 'my_app_project_dir: "/srv/my-app"' in defaults
    assert 'my_app_web_image: "ghcr.io/example/web"' in defaults
    assert 'my_app_web_image_tag: "1.2.3"' in defaults
    assert 'my_app_web_published_port: "8080"' in defaults
    assert 'my_app_web_log_level: "info"' in defaults
    compose_template = (
        role_directory / "templates" / "compose.yaml.j2"
    ).read_bytes().decode("utf-8")
    assert compose_template.startswith("# Preserve comments, quotes, ordering, and CRLF.\r\n")
    assert 'image: "{{ my_app_web_image }}:{{ my_app_web_image_tag }}"' in compose_template
    assert '"{{ my_app_web_published_port }}:80"' in compose_template
    assert "LOG_LEVEL: {{ my_app_web_log_level }}" in compose_template
    generated_defaults = YAML(typ="safe").load(defaults)
    assert isinstance(generated_defaults, dict)
    rendered_source = Environment(
        keep_trailing_newline=True, newline_sequence="\r\n"
    ).from_string(compose_template).render(**generated_defaults)
    assert rendered_source.encode("utf-8") == source_document.encode("utf-8")
    tasks = (role_directory / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert 'project_name: "{{ my_app_compose_project_name }}"' in tasks
    assert 'dest: "{{ my_app_project_dir }}/compose.yaml"' in tasks
    assert 'src: "compose.yaml.j2"' in tasks
    assert 'owner: "0"' in tasks
    assert 'mode: "0640"' in tasks
    assert 'newline_sequence: "\\r\\n"' in tasks
    assert 'files:\n      - "compose.yaml"' in tasks
    assert "compose.yml.j2" not in tasks
    assert "- name: \"Render compose.yaml\"\n  tags:\n    - source\n" in tasks
    assert "- name: Deploy my_app Compose project\n  tags:\n    - compose\n" in tasks
    assert not (role_directory / "templates" / "compose.yml.j2").exists()
    assert not (role_directory / ".sops.yaml").exists()
    assert not (role_directory / "vars" / "secrets.example.yml").exists()
    assert not (role_directory / "vars" / "secrets.sops.yml").exists()


def test_generate_reports_a_byte_identical_remote_role_as_unchanged(tmp_path: Path) -> None:
    """Re-running remote generation against the same source is a no-op."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      LOG_LEVEL: info
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"LOG_LEVEL": "info"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"
    arguments = [
        "generate",
        "--host",
        "web1",
        "--project",
        "my-app",
        "--output",
        str(output_directory),
        "--sops-config",
        str(sops_config),
    ]

    first = CliRunner().invoke(main, arguments, env=environment)
    assert first.exit_code == 0, first.output
    role_directory = output_directory / "my_app"
    before = {
        str(path.relative_to(role_directory)): path.read_bytes()
        for path in sorted(role_directory.rglob("*"))
        if path.is_file()
    }

    second = CliRunner().invoke(main, arguments, env=environment)

    assert second.exit_code == 0, second.output
    assert second.output.splitlines() == [
        "Discovering projects on web1...",
        "✓ my-app -> my_app (unchanged)",
        "",
        "1 unchanged",
    ]
    after = {
        str(path.relative_to(role_directory)): path.read_bytes()
        for path in sorted(role_directory.rglob("*"))
        if path.is_file()
    }
    assert after == before
    assert not (output_directory / ".compose2role").exists()

    json_result = CliRunner().invoke(main, [*arguments, "--format", "json"], env=environment)
    assert json_result.exit_code == 0, json_result.output
    assert json.loads(json_result.output)["projects"][0]["status"] == "unchanged"


def test_generate_remote_diff_reports_path_states_without_writing(tmp_path: Path) -> None:
    """Remote --diff reviews the rendered plan without writing role content."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      LOG_LEVEL: info
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"LOG_LEVEL": "info"},
                "image": "ghcr.io/example/web:1.2.3",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"
    arguments = [
        "generate",
        "--host",
        "web1",
        "--project",
        "my-app",
        "--output",
        str(output_directory),
        "--sops-config",
        str(sops_config),
    ]

    first = CliRunner().invoke(main, arguments, env=environment)
    assert first.exit_code == 0, first.output
    role_directory = output_directory / "my_app"
    before = {
        str(path.relative_to(role_directory)): path.read_bytes()
        for path in sorted(role_directory.rglob("*"))
        if path.is_file()
    }

    changed_source = source_document + "    command: [\"serve\"]\n"
    environment["C2R_SOURCE_DOCUMENT"] = base64.b64encode(
        changed_source.encode("utf-8")
    ).decode("ascii")
    environment["C2R_CANONICAL_DOCUMENT"] = json.dumps(
        {
            "services": {
                "web": {
                    "command": ["serve"],
                    "environment": {"LOG_LEVEL": "info"},
                    "image": "ghcr.io/example/web:1.2.3",
                }
            }
        }
    )
    result = CliRunner().invoke(
        main, [*arguments, "--diff", "--format", "json"], env=environment
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["projects"][0]["status"] == "diff"
    diff = payload["projects"][0]["diff"]
    assert ".compose2role.json" in diff["changed"]
    assert "templates/compose.yaml.j2" in diff["withheld"]
    assert "defaults/main.yml" in diff["unchanged"]
    assert "1.2.3" not in json.dumps(diff)
    after = {
        str(path.relative_to(role_directory)): path.read_bytes()
        for path in sorted(role_directory.rglob("*"))
        if path.is_file()
    }
    assert after == before
    assert not (output_directory / ".compose2role").exists()


def test_generate_hides_warning_findings_unless_verbose(tmp_path: Path) -> None:
    """Default text generation shows errors only; --verbose adds warnings."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    base_arguments = [
        "generate",
        "--host",
        "web1",
        "--project",
        "my-app",
        "--sops-config",
        str(sops_config),
    ]

    quiet = CliRunner().invoke(
        main,
        [*base_arguments, "--output", str(tmp_path / "quiet-roles")],
        env=environment,
    )
    verbose = CliRunner().invoke(
        main,
        [*base_arguments, "--output", str(tmp_path / "verbose-roles"), "--verbose"],
        env=environment,
    )

    assert quiet.exit_code == 0, quiet.output
    assert "C2R001" not in quiet.output
    assert "✓ my-app -> my_app (generated)" in quiet.output
    assert verbose.exit_code == 0, verbose.output
    assert "C2R001" in verbose.output
    assert "WARNING" in verbose.output


def test_generate_uses_a_labeled_compose_project_directory_for_defaults_and_provenance(
    tmp_path: Path,
) -> None:
    """A valid container label supersedes the first Compose file's parent directory."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            **environment,
            "C2R_CONFIG_PATH": "/srv/stacks/my-app/compose/compose.yaml",
            "C2R_WORKING_DIRECTORY_LABEL": "my-app\t/srv/stacks/my-app\n",
        },
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    defaults = (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert 'my_app_project_dir: "/srv/stacks/my-app"' in defaults
    assert (role_directory / "templates" / "compose" / "compose.yaml.j2").is_file()
    provenance = json.loads((role_directory / ".compose2role.json").read_text(encoding="utf-8"))
    assert provenance["source"]["root"] == "/srv/stacks/my-app"


def test_generate_adopts_merge_keys_and_aliases_without_duplicate_edits(tmp_path: Path) -> None:
    """Inherited and aliased values stay literal while direct values remain configurable."""
    source_document = """\
x-common: &common
  image: &common_image ghcr.io/example/shared:1.2.3
  ports: &common_ports
    - &common_port "8080:80"
  environment: &common_environment
    LOG_LEVEL: &common_log info
services:
  merged_one:
    <<: *common
  merged_two:
    <<: *common
  direct:
    <<: *common
    image: ghcr.io/example/direct:2.0.0
    ports:
      - "8081:81"
    environment:
      LOG_LEVEL: debug
  aliases:
    image: *common_image
    ports: *common_ports
    environment: *common_environment
"""
    canonical_document = {
        "services": {
            "aliases": {
                "environment": {"LOG_LEVEL": "info"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/shared:1.2.3",
                "ports": [{"target": 80, "published": "8080", "protocol": "tcp"}],
                "restart": "unless-stopped",
                "user": "1000:1000",
            },
            "direct": {
                "environment": {"LOG_LEVEL": "debug"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/direct:2.0.0",
                "ports": [{"target": 81, "published": "8081", "protocol": "tcp"}],
                "restart": "unless-stopped",
                "user": "1000:1000",
            },
            "merged_one": {
                "environment": {"LOG_LEVEL": "info"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/shared:1.2.3",
                "ports": [{"target": 80, "published": "8080", "protocol": "tcp"}],
                "restart": "unless-stopped",
                "user": "1000:1000",
            },
            "merged_two": {
                "environment": {"LOG_LEVEL": "info"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/shared:1.2.3",
                "ports": [{"target": 80, "published": "8080", "protocol": "tcp"}],
                "restart": "unless-stopped",
                "user": "1000:1000",
            },
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    defaults = (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert 'my_app_direct_image: "ghcr.io/example/direct"' in defaults
    assert 'my_app_direct_image_tag: "2.0.0"' in defaults
    assert 'my_app_direct_published_port: "8081"' in defaults
    assert 'my_app_direct_log_level: "debug"' in defaults
    assert "my_app_merged_one_" not in defaults
    assert "my_app_merged_two_" not in defaults
    assert "my_app_aliases_" not in defaults
    compose_template = (role_directory / "templates" / "compose.yaml.j2").read_text(
        encoding="utf-8"
    )
    assert compose_template.count("    <<: *common\n") == 3
    assert "  image: &common_image ghcr.io/example/shared:1.2.3\n" in compose_template
    assert '    - &common_port "8080:80"\n' in compose_template
    assert "    LOG_LEVEL: &common_log info\n" in compose_template
    assert "    image: *common_image\n" in compose_template
    assert "    ports: *common_ports\n" in compose_template
    assert "    environment: *common_environment\n" in compose_template
    assert "image: {{ my_app_direct_image }}:{{ my_app_direct_image_tag }}" in compose_template
    assert '"{{ my_app_direct_published_port }}:81"' in compose_template
    assert "LOG_LEVEL: {{ my_app_direct_log_level }}" in compose_template
    rendered_source = Environment(keep_trailing_newline=True).from_string(compose_template).render(
        **YAML(typ="safe").load(defaults)
    )
    assert rendered_source.encode("utf-8") == source_document.encode("utf-8")


@pytest.mark.parametrize(
    "source_document_template",
    (
        """\
x-common: &common
  image: ghcr.io/example/web:1.2.3
  environment:
    API_TOKEN: {secret_value}
services:
  web:
    <<: *common
""",
        """\
x-common: &common
  environment: &secret_environment
    API_TOKEN: {secret_value}
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment: *secret_environment
""",
    ),
    ids=("merge", "alias"),
)
def test_generate_rejects_secret_environment_without_direct_source_span(
    tmp_path: Path, source_document_template: str
) -> None:
    """A secret without a direct source span never reaches a generated role."""
    secret_value = "merged-secret-must-not-persist"
    source_document = source_document_template.format(secret_value=secret_value)
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 1, result.output
    assert "remote Compose source has an unsupported secret environment" in result.output
    assert secret_value not in result.output
    assert not output_directory.exists()


def test_generate_rejects_secret_inherited_by_a_partial_environment_override(
    tmp_path: Path,
) -> None:
    """A direct override cannot leave an inherited secret in the template."""
    secret_value = "partial-override-secret-must-not-persist"
    source_document = f"""\
x-common: &common
  image: ghcr.io/example/web:1.2.3
  environment:
    API_TOKEN: {secret_value}
services:
  web:
    <<: *common
    environment:
      LOG_LEVEL: debug
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value, "LOG_LEVEL": "debug"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 1, result.output
    assert "remote Compose source has an unsupported secret environment" in result.output
    assert secret_value not in result.output
    assert not output_directory.exists()


def test_generate_lifts_list_form_environment_secrets_without_plaintext(tmp_path: Path) -> None:
    """A classified list-form environment value is rendered from SOPS, not source plaintext."""
    secret_value = "fixture-$1-secret"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      - LOG_LEVEL=info
      - API_TOKEN={secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value, "LOG_LEVEL": "info"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    _install_stub_command(
        bin_directory,
        "sops",
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$C2R_SOPS_OUTPUT\"\n",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            **environment,
            "C2R_SOPS_OUTPUT": _encrypted_sops_output("my_app_web_api_token"),
        },
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    generated_role_contents = b"".join(
        path.read_bytes() for path in role_directory.rglob("*") if path.is_file()
    )
    assert secret_value.encode("utf-8") not in generated_role_contents
    template = (role_directory / "templates" / "compose.yaml.j2").read_text(encoding="utf-8")
    assert "- LOG_LEVEL={{ my_app_web_log_level }}" in template
    assert "API_TOKEN={{ my_app_secrets['my_app_web_api_token'] }}" in template
    tasks = (role_directory / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "community.sops.load_vars:" in tasks
    assert "- name: Load my_app SOPS secrets\n  tags:\n    - secrets\n" in tasks
    defaults = (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert 'my_app_web_log_level: "info"' in defaults
    assert "  - my_app_web_api_token" in defaults
    rendered = Environment(keep_trailing_newline=True).from_string(template).render(
        **YAML(typ="safe").load(defaults),
        my_app_secrets={"my_app_web_api_token": secret_value},
    )
    assert rendered.encode("utf-8") == source_document.encode("utf-8")


def test_generate_lifts_a_quoted_secret_value_ending_in_a_backslash(tmp_path: Path) -> None:
    """A quoted secret ending in a literal backslash remains source-faithful."""
    effective_secret_value = "fixture\\"
    source_secret_value = r"fixture\\"
    source_document = r"""services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: "fixture\\"
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": effective_secret_value},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    sops_payload = tmp_path / "sops-payload.json"
    _install_stub_command(
        bin_directory,
        "sops",
        "#!/bin/sh\ncat > \"$C2R_SOPS_PAYLOAD\"\nprintf '%s\\n' \"$C2R_SOPS_OUTPUT\"\n",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            **environment,
            "C2R_SOPS_OUTPUT": _encrypted_sops_output("my_app_web_api_token"),
            "C2R_SOPS_PAYLOAD": str(sops_payload),
        },
    )

    assert result.exit_code == 0, result.output
    assert json.loads(sops_payload.read_text(encoding="utf-8")) == {
        "my_app_web_api_token": source_secret_value
    }
    role_directory = output_directory / "my_app"
    generated_role_contents = b"".join(
        path.read_bytes() for path in role_directory.rglob("*") if path.is_file()
    )
    assert source_secret_value.encode("utf-8") not in generated_role_contents
    assert effective_secret_value.encode("utf-8") not in generated_role_contents
    template = (role_directory / "templates" / "compose.yaml.j2").read_text(encoding="utf-8")
    assert 'API_TOKEN: "{{ my_app_secrets[\'my_app_web_api_token\'] }}"' in template
    defaults = YAML(typ="safe").load(
        (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    )
    assert isinstance(defaults, dict)
    rendered = Environment(keep_trailing_newline=True).from_string(template).render(
        **defaults,
        my_app_secrets={"my_app_web_api_token": source_secret_value},
    )
    assert rendered.encode("utf-8") == source_document.encode("utf-8")


def test_generate_preserves_plain_block_scalar_environment_values(tmp_path: Path) -> None:
    """An unparameterizable plain scalar stays literal instead of failing adoption."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      LOG_LEVEL: info
      CONFIG_TEXT: >-
        hello
        world
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"CONFIG_TEXT": "hello world", "LOG_LEVEL": "info"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    template = (role_directory / "templates" / "compose.yaml.j2").read_text(encoding="utf-8")
    assert "CONFIG_TEXT: >-\n        hello\n        world\n" in template
    defaults = (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert 'my_app_web_log_level: "info"' in defaults
    assert "my_app_web_config_text" not in defaults


def test_generate_parameterizes_short_and_long_form_published_ports(tmp_path: Path) -> None:
    """Host-IP, protocol, and long-form port declarations retain their source and knob."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    ports:
      - "127.0.0.1:8080:80/udp"
      - target: 443
        published: "8443"
        protocol: tcp
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "ports": [
                    {"published": "8080", "target": 80, "protocol": "udp"},
                    {"published": "8443", "target": 443, "protocol": "tcp"},
                ],
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    defaults = (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert 'my_app_web_published_port_1: "8080"' in defaults
    assert 'my_app_web_published_port_2: "8443"' in defaults
    template = (role_directory / "templates" / "compose.yaml.j2").read_text(encoding="utf-8")
    assert '"127.0.0.1:{{ my_app_web_published_port_1 }}:80/udp"' in template
    assert 'published: "{{ my_app_web_published_port_2 }}"' in template
    rendered = Environment(keep_trailing_newline=True).from_string(template).render(
        **YAML(typ="safe").load(defaults)
    )
    assert rendered.encode("utf-8") == source_document.encode("utf-8")


def test_generated_role_adopts_a_matching_source_tree_without_changes(tmp_path: Path) -> None:
    """Matching source is idempotent and unsafe file-secret targets are refused."""
    source_document = b"""\
# Existing source remains in place.
services:
  web:
    image: "ghcr.io/example/web:1.2.3"
secrets:
  app_secret:
    file: ./secrets/app.bin
"""
    secret_bytes = b"\x00adopted-secret\n"
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"my-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/my-app/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    case "$path" in
      /srv/my-app/compose.yaml)
        printf 'file %s %s %s\\n' "$C2R_SOURCE_MODE" "$C2R_SOURCE_UID" "$C2R_SOURCE_GID"
        printf '%s\\n' "$C2R_SOURCE_DOCUMENT"
        ;;
      /srv/my-app/secrets/app.bin)
        printf 'file 600 %s %s\\n' "$C2R_SECRET_UID" "$C2R_SECRET_GID"
        printf '%s\\n' "$C2R_SECRET_SOURCE"
        ;;
      *) exit 98 ;;
    esac
    ;;
  stat)
    case "$path" in
      /srv/my-app/.env) printf '%s\\n' missing ;;
      /srv/my-app/secrets/app.bin) printf '%s\\n' file ;;
      *) exit 98 ;;
    esac
    ;;
  config)
    printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
    ;;
  *) exit 97 ;;
esac
""",
    )
    _install_stub_command(
        bin_directory,
        "sops",
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$C2R_SOPS_OUTPUT\"\n",
    )
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    output_directory = tmp_path / "roles"
    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
            "C2R_SECRET_GID": str(os.getgid()),
            "C2R_SECRET_SOURCE": base64.b64encode(secret_bytes).decode("ascii"),
            "C2R_SECRET_UID": str(os.getuid()),
            "C2R_SOURCE_DOCUMENT": base64.b64encode(source_document).decode("ascii"),
            "C2R_SOURCE_GID": str(os.getgid()),
            "C2R_SOURCE_MODE": "640",
            "C2R_SOURCE_UID": str(os.getuid()),
            "C2R_SOPS_OUTPUT": _encrypted_sops_output("my_app_secret_app_secret"),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    assert not (role_directory / "README.md").exists()
    tasks = (role_directory / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "my_app_secret_app_secret" in tasks
    assert "secrets/app.bin" in tasks
    source_tree = tmp_path / "matching-source"
    source_tree.mkdir()
    compose_file = source_tree / "compose.yaml"
    compose_file.write_bytes(source_document)
    compose_file.chmod(0o640)
    secret_file = source_tree / "secrets" / "app.bin"
    secret_file.parent.mkdir()
    secret_file.write_bytes(secret_bytes)
    secret_file.chmod(0o600)
    original_checksum = hashlib.sha256(compose_file.read_bytes()).digest()
    original_secret_checksum = hashlib.sha256(secret_file.read_bytes()).digest()
    fake_collection_root = tmp_path / "fake-collections"
    module_directory = (
        fake_collection_root
        / "ansible_collections"
        / "community"
        / "docker"
        / "plugins"
        / "modules"
    )
    module_directory.mkdir(parents=True)
    (module_directory / "docker_compose_v2.py").write_text(
        """\
from ansible.module_utils.basic import AnsibleModule

module = AnsibleModule(
    argument_spec={
        "files": {"type": "list", "elements": "str", "required": True},
        "project_name": {"type": "str", "required": True},
        "project_src": {"type": "str", "required": True},
        "pull": {"type": "str", "required": True},
        "recreate": {"type": "str", "required": True},
        "remove_orphans": {"type": "bool", "required": True},
        "state": {"type": "str", "required": True},
    }
)
if module.params["files"] != ["compose.yaml"] or module.params["project_name"] != "my-app":
    module.fail_json(msg="unexpected source-fidelity Compose invocation")
module.exit_json(changed=False)
""",
        encoding="utf-8",
    )
    sops_action_directory = (
        fake_collection_root
        / "ansible_collections"
        / "community"
        / "sops"
        / "plugins"
        / "action"
    )
    sops_action_directory.mkdir(parents=True)
    (sops_action_directory / "load_vars.py").write_text(
        """\
from __future__ import annotations

import os

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        result["ansible_facts"] = {
            self._task.args["name"]: {
                "my_app_secret_app_secret": os.environ["C2R_TEST_SECRET_BASE64"],
            }
        }
        return result
""",
        encoding="utf-8",
    )
    playbook = tmp_path / "adopt.yml"
    playbook.write_text(
        f"""\
---
- name: Adopt a matching source tree
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    my_app_project_dir: {json.dumps(str(source_tree))}
  roles:
    - my_app
""",
        encoding="utf-8",
    )
    configured_bin = os.environ.get("COMPOSE2ROLE_ANSIBLE_BIN")
    ansible_playbook = (
        str(Path(configured_bin) / "ansible-playbook") if configured_bin else "ansible-playbook"
    )
    validation_environment = {
        **os.environ,
        "ANSIBLE_COLLECTIONS_PATH": (
            f"{fake_collection_root}:{Path(__file__).parents[1] / 'collections'}"
        ),
        "ANSIBLE_ROLES_PATH": str(output_directory),
        "C2R_TEST_SECRET_BASE64": base64.b64encode(secret_bytes).decode("ascii"),
    }
    for _ in range(2):
        apply_result = subprocess.run(
            [ansible_playbook, "--inventory", "localhost,", str(playbook)],
            check=False,
            capture_output=True,
            env=validation_environment,
            text=True,
        )
        assert apply_result.returncode == 0, apply_result.stdout + apply_result.stderr
        assert "changed=0" in apply_result.stdout
        assert hashlib.sha256(compose_file.read_bytes()).digest() == original_checksum
        assert hashlib.sha256(secret_file.read_bytes()).digest() == original_secret_checksum

    def apply_unsafe_target(project_directory: Path) -> subprocess.CompletedProcess[str]:
        unsafe_playbook = tmp_path / f"{project_directory.name}.yml"
        unsafe_playbook.write_text(
            f"""\
---
- name: Refuse an unsafe file-secret target
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    my_app_project_dir: {json.dumps(str(project_directory))}
  roles:
    - my_app
""",
            encoding="utf-8",
        )
        return subprocess.run(
            [ansible_playbook, "--inventory", "localhost,", str(unsafe_playbook)],
            check=False,
            capture_output=True,
            env=validation_environment,
            text=True,
        )

    symlink_project = tmp_path / "symlink-target"
    symlink_target = symlink_project / "secrets" / "app.bin"
    symlink_target.parent.mkdir(parents=True)
    outside_target = tmp_path / "outside-secret"
    outside_target.write_bytes(b"outside-target")
    symlink_target.symlink_to(outside_target)
    symlink_result = apply_unsafe_target(symlink_project)

    assert symlink_result.returncode != 0
    assert outside_target.read_bytes() == b"outside-target"
    assert base64.b64encode(secret_bytes).decode("ascii") not in (
        symlink_result.stdout + symlink_result.stderr
    )

    directory_project = tmp_path / "directory-target"
    directory_target = directory_project / "secrets" / "app.bin"
    directory_target.mkdir(parents=True)
    directory_result = apply_unsafe_target(directory_project)

    assert directory_result.returncode != 0
    assert not tuple(directory_target.iterdir())
    assert base64.b64encode(secret_bytes).decode("ascii") not in (
        directory_result.stdout + directory_result.stderr
    )


def test_generate_preserves_external_compose_prerequisites(tmp_path: Path) -> None:
    """External config and secret declarations stay visible to the deployment operator."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
configs:
  app_config:
    external: true
secrets:
  db_password:
    external: true
"""
    canonical_document = {
        "configs": {"app_config": {"external": True, "name": "shared_config"}},
        "secrets": {"db_password": {"external": True, "name": "shared_db_password"}},
        "services": {
            "web": {
                "configs": [{"source": "app_config", "target": "/etc/app/config.yml"}],
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "secrets": [{"source": "db_password", "target": "db_password"}],
                "user": "1000:1000",
            }
        },
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    compose_template = (role_directory / "templates" / "compose.yaml.j2").read_text(
        encoding="utf-8"
    )
    assert "app_config:" in compose_template
    assert "db_password:" in compose_template
    assert "external: true" in compose_template
    assert not (role_directory / "README.md").exists()
    assert (
        "  prerequisites: external config app_config, external secret db_password"
        in result.output
    )


def test_generate_adopts_dotenv_files_and_preserves_bind_mounts(tmp_path: Path) -> None:
    """Adoption templates approved dotenv inputs but never captures bind-mounted data."""
    compose_source = """\
# Keep this hand-maintained bind declaration.
services:
  web:
    image: ghcr.io/example/web:1.2.3
    env_file: env/web.env
    environment:
      - LOG_LEVEL=${LOG_LEVEL}
      - API_TOKEN=${APP_VALUE}
    volumes:
      - ${UPLOAD_LOCATION}:/var/lib/web
networks:
  internal:
  shared:
    external: true
"""
    root_dotenv = """\
# Keep dotenv comments and ordering.
LOG_LEVEL=info
APP_VALUE=fixture-dotenv-secret
UPLOAD_LOCATION=/srv/web-data
UNUSED_TOKEN=unused-secret-value
"""
    service_dotenv = """\
DATABASE_URL=postgres://operator:dotenv-password@db.example/web
"""
    canonical_document = {
        "networks": {"internal": {}, "shared": {"external": True}},
        "services": {
            "web": {
                "environment": {
                    "API_TOKEN": "fixture-dotenv-secret",
                    "DATABASE_URL": "postgres://operator:dotenv-password@db.example/web",
                    "LOG_LEVEL": "info",
                },
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
                "volumes": [
                    {"source": "/srv/web-data", "target": "/var/lib/web", "type": "bind"}
                ],
            }
        },
    }
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"my-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/my-app/docker-compose.yml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
printf '%s\\n' "$payload" >> "$C2R_PAYLOAD_LOG"
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    printf '%s\\n' 'file 640 1000 1001'
    case "$path" in
      /srv/my-app/docker-compose.yml) printf '%s\\n' "$C2R_COMPOSE_SOURCE" ;;
      /srv/my-app/.env) printf '%s\\n' "$C2R_ROOT_DOTENV" ;;
      /srv/my-app/env/web.env) printf '%s\\n' "$C2R_SERVICE_DOTENV" ;;
      *) exit 98 ;;
    esac
    ;;
  stat)
    case "$path" in
      /srv/my-app/.env|/srv/my-app/env/web.env) printf '%s\\n' file ;;
      *) exit 98 ;;
    esac
    ;;
  config)
    printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
    ;;
  *)
    exit 97
    ;;
esac
""",
    )
    _install_stub_command(
        bin_directory,
        "sops",
        """\
#!/bin/sh
cat > "$C2R_SOPS_PAYLOAD"
cat <<'EOF'
sops:
  mac: ENC[AES256_GCM,data:fixture]
my_app_dotenv_env_app_value: ENC[AES256_GCM,data:fixture]
my_app_dotenv_env_log_level: ENC[AES256_GCM,data:fixture]
my_app_dotenv_env_web_env_database_url: ENC[AES256_GCM,data:fixture]
EOF
""",
    )
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    output_directory = tmp_path / "roles"
    payload_log = tmp_path / "payloads"
    sops_payload = tmp_path / "sops-payload.json"
    secret_policy_path = tmp_path / "policy.toml"
    secret_policy_path.write_text(
        """\
[[dotenv_rules]]
project = "my-app"
source = ".env"
key = "LOG_LEVEL"
decision = "secret"

[[dotenv_rules]]
project = "my-app"
source = ".env"
key = "UNUSED_TOKEN"
decision = "plain"
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--secret-policy",
            str(secret_policy_path),
            "--sops-config",
            str(sops_config),
        ],
        env={
            "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
            "C2R_COMPOSE_SOURCE": base64.b64encode(compose_source.encode("utf-8")).decode("ascii"),
            "C2R_ROOT_DOTENV": base64.b64encode(root_dotenv.encode("utf-8")).decode("ascii"),
            "C2R_SERVICE_DOTENV": base64.b64encode(service_dotenv.encode("utf-8")).decode(
                "ascii"
            ),
            "C2R_PAYLOAD_LOG": str(payload_log),
            "C2R_SOPS_PAYLOAD": str(sops_payload),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 0, result.output
    assert json.loads(sops_payload.read_text(encoding="utf-8")) == {
        "my_app_dotenv_env_app_value": "fixture-dotenv-secret",
        "my_app_dotenv_env_log_level": "info",
        "my_app_dotenv_env_web_env_database_url": (
            "postgres://operator:dotenv-password@db.example/web"
        ),
    }
    role_directory = output_directory / "my_app"
    assert (role_directory / "templates" / "docker-compose.yml.j2").is_file()
    assert (role_directory / "templates" / ".env.j2").is_file()
    assert (role_directory / "templates" / "env" / "web.env.j2").is_file()
    compose_template = (role_directory / "templates" / "docker-compose.yml.j2").read_text(
        encoding="utf-8"
    )
    assert "${UPLOAD_LOCATION}:/var/lib/web" in compose_template
    assert "internal:" in compose_template
    assert "external: true" in compose_template
    defaults = (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert "my_app_dotenv_env_app_value:" not in defaults
    assert "my_app_dotenv_env_log_level:" not in defaults
    assert 'my_app_dotenv_env_upload_location: "/srv/web-data"' in defaults
    assert 'my_app_dotenv_env_unused_token: "unused-secret-value"' in defaults
    assert "my_app_dotenv_env_web_env_database_url" in defaults
    generated_role_contents = b"".join(
        path.read_bytes() for path in role_directory.rglob("*") if path.is_file()
    )
    assert b"fixture-dotenv-secret" not in generated_role_contents
    assert b"dotenv-password" not in generated_role_contents
    payloads = payload_log.read_text(encoding="utf-8")
    assert "capture\n/srv/my-app/docker-compose.yml" in payloads
    assert "capture\n/srv/my-app/.env" in payloads
    assert "capture\n/srv/my-app/env/web.env" in payloads
    assert "/srv/web-data" not in payloads


def test_generate_adopts_ordered_multifile_source_tree(tmp_path: Path) -> None:
    """Ordered Compose files retain their relative layout and render their exact source bytes."""
    primary_source = b"""\
# Primary Compose source.\r
services:\r
  web:\r
    image: \"ghcr.io/example/web:1.2.3\"\r
    ports: !override\r
      - "8080:80"\r
    environment: !override\r
      LOG_LEVEL: info\r
"""
    override_source = b"""\
# Override source stays separate.
services:
  web:
    ports: !reset
      - "9080:80"
    environment: !reset
      LOG_LEVEL: debug
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"LOG_LEVEL": "debug"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "ports": [{"target": 80, "published": "9080", "protocol": "tcp"}],
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"my-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":["/srv/my-app/docker-compose.yml",'
  printf '%s\\n' '"/srv/my-app/compose/override.yml"]}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
printf '%s\\n' "$payload" >> "$C2R_PAYLOAD_LOG"
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    printf '%s\\n' 'file 640 1000 1001'
    case "$path" in
      /srv/my-app/docker-compose.yml) printf '%s\\n' "$C2R_PRIMARY_SOURCE" ;;
      /srv/my-app/compose/override.yml) printf '%s\\n' "$C2R_OVERRIDE_SOURCE" ;;
      *) exit 98 ;;
    esac
    ;;
  stat)
    [ "$path" = /srv/my-app/.env ] || exit 98
    printf '%s\\n' missing
    ;;
  config)
    printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
    ;;
  *) exit 97 ;;
esac
""",
    )
    _install_stub_command(bin_directory, "sops", "#!/bin/sh\nexit 99\n")
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    output_directory = tmp_path / "roles"
    payload_log = tmp_path / "payloads"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
            "C2R_OVERRIDE_SOURCE": base64.b64encode(override_source).decode("ascii"),
            "C2R_PAYLOAD_LOG": str(payload_log),
            "C2R_PRIMARY_SOURCE": base64.b64encode(primary_source).decode("ascii"),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    defaults = YAML(typ="safe").load(
        (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    )
    assert isinstance(defaults, dict)
    for relative_path, source, newline_sequence in (
        ("docker-compose.yml", primary_source, "\r\n"),
        ("compose/override.yml", override_source, "\n"),
    ):
        template = (
            role_directory / "templates" / f"{relative_path}.j2"
        ).read_bytes().decode("utf-8")
        rendered = Environment(
            keep_trailing_newline=True, newline_sequence=newline_sequence
        ).from_string(template).render(**defaults)
        assert rendered.encode("utf-8") == source
    tasks = (role_directory / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert 'files:\n      - "docker-compose.yml"\n      - "compose/override.yml"' in tasks
    payloads = payload_log.read_text(encoding="utf-8")
    assert payloads.index("capture\n/srv/my-app/docker-compose.yml") < payloads.index(
        "capture\n/srv/my-app/compose/override.yml"
    )
    _assert_generated_role_validates(tmp_path, output_directory, "my_app")


@pytest.mark.parametrize(
    "source_document",
    (
        """\
services:
  web:
    image: !override fixture-secret-value
""",
        """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment: !unsupported
      API_TOKEN: fixture-secret-value
""",
    ),
)
def test_generate_rejects_unsupported_yaml_tags(tmp_path: Path, source_document: str) -> None:
    """Only Compose reset and override collection tags are accepted from source."""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 1, result.output
    assert "remote Compose source has an unsupported YAML tag" in result.output
    assert "fixture-secret-value" not in result.output
    assert not output_directory.exists()


@pytest.mark.parametrize(
    ("primary_environment", "override_environment", "canonical_environment", "plain_value"),
    (
        (
            "    environment:\n      DATABASE_URL: postgres://operator:fixture-source-secret@db/app\n",
            "    environment:\n      DATABASE_URL: postgres://plain@db/app\n",
            {"DATABASE_URL": "postgres://plain@db/app"},
            "postgres://plain@db/app",
        ),
        (
            "    environment:\n      - DATABASE_URL=postgres://operator:fixture-source-secret@db/app\n",
            "    environment:\n      - DATABASE_URL=postgres://plain@db/app\n",
            {"DATABASE_URL": "postgres://plain@db/app"},
            "postgres://plain@db/app",
        ),
        (
            "    environment:\n      DATABASE_URL: postgres://operator:fixture-source-secret@db/app\n",
            "    environment: !reset []\n",
            {},
            None,
        ),
    ),
    ids=("mapping-override", "list-override", "reset-removed"),
)
def test_generate_classifies_each_multifile_environment_occurrence(
    tmp_path: Path,
    primary_environment: str,
    override_environment: str,
    canonical_environment: dict[str, str],
    plain_value: str | None,
) -> None:
    """A source-only secret never becomes a plaintext default after an override."""
    secret_value = "postgres://operator:fixture-source-secret@db/app"
    source_identity = (
        "compose:compose.yaml:web:environment-list:0:DATABASE_URL"
        if "- DATABASE_URL" in primary_environment
        else "compose:compose.yaml:web:environment:DATABASE_URL"
    )
    secret_key = "my_app_web_database_url"
    if plain_value is not None:
        source_digest = hashlib.sha256(source_identity.encode()).hexdigest()[:8]
        secret_key = f"{secret_key}_{source_digest}"
    primary_source = (
        "services:\n"
        "  web:\n"
        "    image: ghcr.io/example/web:1.2.3\n"
        f"{primary_environment}"
    ).encode()
    override_source = (
        "services:\n"
        "  web:\n"
        f"{override_environment}"
    ).encode()
    canonical_document = {
        "services": {
            "web": {
                "environment": canonical_environment,
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"my-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":["/srv/my-app/compose.yaml",'
  printf '%s\\n' '"/srv/my-app/compose.override.yaml"]}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    printf '%s\\n' 'file 640 1000 1001'
    case "$path" in
      /srv/my-app/compose.yaml) printf '%s\\n' "$C2R_PRIMARY_SOURCE" ;;
      /srv/my-app/compose.override.yaml) printf '%s\\n' "$C2R_OVERRIDE_SOURCE" ;;
      *) exit 98 ;;
    esac
    ;;
  stat)
    [ "$path" = /srv/my-app/.env ] || exit 98
    printf '%s\\n' missing
    ;;
  config)
    printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
    ;;
  *) exit 97 ;;
esac
""",
    )
    _install_stub_command(
        bin_directory,
        "sops",
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$C2R_SOPS_OUTPUT\"\n",
    )
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
            "C2R_OVERRIDE_SOURCE": base64.b64encode(override_source).decode("ascii"),
            "C2R_PRIMARY_SOURCE": base64.b64encode(primary_source).decode("ascii"),
            "C2R_SOPS_OUTPUT": _encrypted_sops_output(secret_key),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    generated_role_contents = b"".join(
        path.read_bytes() for path in role_directory.rglob("*") if path.is_file()
    )
    assert secret_value.encode("utf-8") not in generated_role_contents
    primary_template = (role_directory / "templates" / "compose.yaml.j2").read_text(
        encoding="utf-8"
    )
    assert "my_app_secrets[" in primary_template
    defaults = (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    if plain_value is not None:
        assert plain_value in defaults


def test_generate_refuses_a_source_only_service_with_a_secret_environment(tmp_path: Path) -> None:
    """A service removed from the canonical model cannot leave a source secret literal behind."""
    secret_value = "postgres://operator:source-only-secret@db/app"
    source_document = f"""\
services:
  stale:
    image: ghcr.io/example/stale:1.2.3
    environment:
      DATABASE_URL: {secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 1, result.output
    assert "remote Compose source has an unsupported secret environment" in result.output
    assert secret_value not in result.output
    assert not output_directory.exists()


def test_generate_refuses_an_unused_extension_anchor_with_a_secret_environment(
    tmp_path: Path,
) -> None:
    """A captured extension anchor cannot preserve a secret the role cannot parameterize."""
    secret_value = "postgres://operator:unused-anchor-secret@db/app"
    source_document = f"""\
x-common:
  environment:
    DATABASE_URL: {secret_value}
services:
  web:
    image: ghcr.io/example/web:1.2.3
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 1, result.output
    assert "remote Compose source has an unsupported secret environment" in result.output
    assert secret_value not in result.output
    assert not output_directory.exists()


def test_generate_refuses_file_backed_remote_configs(tmp_path: Path) -> None:
    """A role does not claim to carry a remote file-backed Compose config."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
configs:
  app_config:
    file: ./app.conf
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 1, result.output
    assert "C2R027: remote file-backed Compose configs are not supported" in result.output
    assert not output_directory.exists()


def test_generate_imports_binary_file_backed_compose_secrets(tmp_path: Path) -> None:
    """A contained file secret is encrypted and restored at its original path and metadata."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
secrets:
  app_secret:
    file: ./secrets/app.bin
"""
    secret_bytes = b"\x00binary\xffsecret\n"
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"my-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/my-app/docker-compose.yml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    case "$path" in
      /srv/my-app/docker-compose.yml)
        printf '%s\\n' 'file 640 1000 1001'
        printf '%s\\n' "$C2R_COMPOSE_SOURCE"
        ;;
      /srv/my-app/secrets/app.bin)
        printf '%s\\n' 'file 600 1002 1003'
        printf '%s\\n' "$C2R_SECRET_SOURCE"
        ;;
      *) exit 98 ;;
    esac
    ;;
  stat)
    case "$path" in
      /srv/my-app/.env) printf '%s\\n' missing ;;
      /srv/my-app/secrets/app.bin) printf '%s\\n' file ;;
      *) exit 98 ;;
    esac
    ;;
  config)
    printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
    ;;
  *) exit 97 ;;
esac
""",
    )
    _install_stub_command(
        bin_directory,
        "sops",
        """\
#!/bin/sh
payload=$(cat)
case "$payload" in
  *"$C2R_EXPECTED_BASE64"*) ;;
  *) exit 98 ;;
esac
cat <<'EOF'
sops:
  mac: ENC[AES256_GCM,data:fixture]
my_app_secret_app_secret: ENC[AES256_GCM,data:fixture]
EOF
""",
    )
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
            "C2R_COMPOSE_SOURCE": base64.b64encode(source_document.encode("utf-8")).decode(
                "ascii"
            ),
            "C2R_EXPECTED_BASE64": base64.b64encode(secret_bytes).decode("ascii"),
            "C2R_SECRET_SOURCE": base64.b64encode(secret_bytes).decode("ascii"),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    tasks = (role_directory / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "my_app_secret_app_secret" in tasks
    assert "secrets/app.bin" in tasks
    assert 'mode: "0600"' in tasks
    assert "base64 --decode" in tasks
    assert "file: ./secrets/app.bin" in (
        role_directory / "templates" / "docker-compose.yml.j2"
    ).read_text(encoding="utf-8")
    generated_role_contents = b"".join(
        path.read_bytes() for path in role_directory.rglob("*") if path.is_file()
    )
    assert secret_bytes not in generated_role_contents
    assert base64.b64encode(secret_bytes) not in generated_role_contents
    _assert_generated_role_validates(tmp_path, output_directory, "my_app")


def test_generate_accepts_empty_secrets_left_unencrypted_by_sops(tmp_path: Path) -> None:
    """SOPS leaves empty values plaintext; an empty secret carries nothing to protect."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: ""
secrets:
  app_secret:
    file: ./secrets/empty.bin
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": ""},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"my-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/my-app/docker-compose.yml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    case "$path" in
      /srv/my-app/docker-compose.yml)
        printf '%s\\n' 'file 640 1000 1001'
        printf '%s\\n' "$C2R_COMPOSE_SOURCE"
        ;;
      /srv/my-app/secrets/empty.bin)
        printf '%s\\n' 'file 600 1002 1003'
        printf '\\n'
        ;;
      *) exit 98 ;;
    esac
    ;;
  stat)
    case "$path" in
      /srv/my-app/.env) printf '%s\\n' missing ;;
      /srv/my-app/secrets/empty.bin) printf '%s\\n' file ;;
      *) exit 98 ;;
    esac
    ;;
  config)
    printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
    ;;
  *) exit 97 ;;
esac
""",
    )
    _install_stub_command(
        bin_directory,
        "sops",
        """\
#!/bin/sh
cat >/dev/null
cat <<'EOF'
sops:
  mac: ENC[AES256_GCM,data:fixture]
my_app_secret_app_secret: ""
my_app_web_api_token: ""
EOF
""",
    )
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
            "C2R_COMPOSE_SOURCE": base64.b64encode(source_document.encode("utf-8")).decode(
                "ascii"
            ),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    secrets = (role_directory / "vars" / "secrets.sops.yml").read_text(encoding="utf-8")
    assert 'my_app_secret_app_secret: ""' in secrets
    assert 'my_app_web_api_token: ""' in secrets
    tasks = (role_directory / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "my_app_secret_app_secret" in tasks
    assert "secrets/empty.bin" in tasks
    assert "base64 --decode" in tasks


def test_generate_accepts_short_secrets_that_appear_inside_ciphertext(tmp_path: Path) -> None:
    """A plaintext value can coincide with ciphertext characters without a leak."""
    secret_value = "x"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: {secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    _install_stub_command(
        bin_directory,
        "sops",
        """\
#!/bin/sh
cat >/dev/null
cat <<'EOF'
my_app_web_api_token: ENC[AES256_GCM,data:x==,iv:x==,tag:x==,type:str]
sops:
  mac: ENC[AES256_GCM,data:x==]
EOF
""",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    secrets = (output_directory / "my_app" / "vars" / "secrets.sops.yml").read_text(
        encoding="utf-8"
    )
    assert "my_app_web_api_token: ENC[" in secrets


def test_generate_refuses_escaping_file_backed_compose_secret_paths(tmp_path: Path) -> None:
    """A secret input outside the project root fails without naming or copying it."""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    for name, reference in (
        ("parent", "../outside.txt"),
        ("absolute", "/etc/passwd"),
    ):
        case_directory = tmp_path / name
        case_directory.mkdir()
        source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
secrets:
  app_secret:
    file: {reference}
"""
        environment, sops_config = _remote_environment(
            case_directory, source_document, canonical_document
        )
        output_directory = case_directory / "roles"

        result = CliRunner().invoke(
            main,
            [
                "generate",
                "--host",
                "web1",
                "--project",
                "my-app",
                "--output",
                str(output_directory),
                "--sops-config",
                str(sops_config),
            ],
            env=environment,
        )

        assert result.exit_code == 1, result.output
        assert "remote file-backed Compose secret path escapes the project root" in result.output
        assert reference not in result.output
        assert not output_directory.exists()


def test_generate_disambiguates_colliding_file_secret_sops_keys(tmp_path: Path) -> None:
    """Colliding normalized Compose secret names receive stable distinct SOPS keys."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
secrets:
  app-token:
    file: ./secrets/first.bin
  app_token:
    file: ./secrets/second.bin
"""
    first_secret = b"\x00first-secret\n"
    second_secret = b"\xffsecond-secret\n"
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"my-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/my-app/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    case "$path" in
      /srv/my-app/compose.yaml)
        printf '%s\\n' 'file 640 0 0'
        printf '%s\\n' "$C2R_COMPOSE_SOURCE"
        ;;
      /srv/my-app/secrets/first.bin)
        printf '%s\\n' 'file 600 0 0'
        printf '%s\\n' "$C2R_FIRST_SECRET_SOURCE"
        ;;
      /srv/my-app/secrets/second.bin)
        printf '%s\\n' 'file 600 0 0'
        printf '%s\\n' "$C2R_SECOND_SECRET_SOURCE"
        ;;
      *) exit 98 ;;
    esac
    ;;
  stat)
    case "$path" in
      /srv/my-app/.env) printf '%s\\n' missing ;;
      /srv/my-app/secrets/first.bin|/srv/my-app/secrets/second.bin) printf '%s\\n' file ;;
      *) exit 98 ;;
    esac
    ;;
  config)
    printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
    ;;
  *) exit 97 ;;
esac
""",
    )
    _install_stub_command(
        bin_directory,
        "sops",
        """\
#!/bin/sh
cat > "$C2R_SOPS_PAYLOAD"
printf '%s\\n' "$C2R_SOPS_OUTPUT"
""",
    )
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    first_payload_path = tmp_path / "first-sops-payload.json"
    environment = {
        "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
        "C2R_COMPOSE_SOURCE": base64.b64encode(source_document.encode("utf-8")).decode("ascii"),
        "C2R_FIRST_SECRET_SOURCE": base64.b64encode(first_secret).decode("ascii"),
        "C2R_SECOND_SECRET_SOURCE": base64.b64encode(second_secret).decode("ascii"),
        "C2R_SOPS_OUTPUT": _encrypted_sops_output(
            *(
                "my_app_secret_app_token_"
                + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:8]
                for identity in (
                    "file-secret:app-token:secrets/first.bin",
                    "file-secret:app_token:secrets/second.bin",
                )
            )
        ),
        "C2R_SOPS_PAYLOAD": str(first_payload_path),
        "PATH": f"{bin_directory}:{os.environ['PATH']}",
    }
    arguments = [
        "generate",
        "--host",
        "web1",
        "--project",
        "my-app",
        "--sops-config",
        str(sops_config),
    ]
    output_directory = tmp_path / "roles"

    first_result = CliRunner().invoke(
        main,
        [*arguments, "--output", str(output_directory)],
        env=environment,
    )

    assert first_result.exit_code == 0, first_result.output
    second_payload_path = tmp_path / "second-sops-payload.json"
    second_result = CliRunner().invoke(
        main,
        [*arguments, "--output", str(tmp_path / "roles-again")],
        env={**environment, "C2R_SOPS_PAYLOAD": str(second_payload_path)},
    )

    assert second_result.exit_code == 0, second_result.output
    first_payload = json.loads(first_payload_path.read_text(encoding="utf-8"))
    assert first_payload == json.loads(second_payload_path.read_text(encoding="utf-8"))
    assert set(first_payload.values()) == {
        base64.b64encode(first_secret).decode("ascii"),
        base64.b64encode(second_secret).decode("ascii"),
    }
    keys = set(first_payload)
    prefix = "my_app_secret_app_token_"
    assert len(keys) == 2
    assert all(
        key.startswith(prefix)
        and len(key) == len(prefix) + 8
        and all(character in "0123456789abcdef" for character in key[len(prefix) :])
        for key in keys
    )
    tasks = (output_directory / "my_app" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert all(f'key: "{key}"' in tasks for key in keys)
    generated_role_contents = b"".join(
        path.read_bytes() for path in (output_directory / "my_app").rglob("*") if path.is_file()
    )
    assert first_secret not in generated_role_contents
    assert second_secret not in generated_role_contents
    assert base64.b64encode(first_secret) not in generated_role_contents
    assert base64.b64encode(second_secret) not in generated_role_contents


def test_generate_refuses_secret_shaped_non_environment_keys(tmp_path: Path) -> None:
    """A secret-shaped label is refused rather than rendered as an unprotected value."""
    secret_value = "do-not-render-this-label-value"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    labels:
      API_TOKEN: {secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "labels": {"API_TOKEN": secret_value},
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 1, result.output
    assert (
        "C2R029: remote non-environment secret-shaped mapping keys are not supported"
        in result.output
    )
    assert secret_value not in result.output
    assert not output_directory.exists()


def test_generate_preserves_canonical_no_file_topology(tmp_path: Path) -> None:
    """Ordinary source topology survives source-faithful remote role generation."""
    source_document = """\
networks:
  backplane:
    name: my-app_backplane
services:
  db:
    image: "postgres:16"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready"]
    networks:
      - backplane
    restart: unless-stopped
    user: "1000:1000"
    volumes:
      - type: volume
        source: db_data
        target: /var/lib/postgresql/data
  web:
    image: "ghcr.io/example/web:1.2.3"
    command: ["serve", "--mode", "production"]
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "true"]
    labels:
      org.example.component: web
    networks:
      - backplane
    restart: unless-stopped
    user: "1000:1000"
volumes:
  db_data:
    name: my-app_db_data
"""
    canonical_document = {
        "networks": {"backplane": {"name": "my-app_backplane"}},
        "services": {
            "db": {
                "environment": {},
                "healthcheck": {"test": ["CMD-SHELL", "pg_isready"]},
                "image": "postgres:16",
                "networks": ["backplane"],
                "restart": "unless-stopped",
                "user": "1000:1000",
                "volumes": [
                    {"source": "db_data", "target": "/var/lib/postgresql/data", "type": "volume"}
                ],
            },
            "web": {
                "command": ["serve", "--mode", "production"],
                "depends_on": {"db": {"condition": "service_healthy"}},
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "labels": {"org.example.component": "web"},
                "networks": ["backplane"],
                "restart": "unless-stopped",
                "user": "1000:1000",
            },
        },
        "volumes": {"db_data": {"name": "my-app_db_data"}},
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    template = YAML(typ="safe").load(
        (output_directory / "my_app" / "templates" / "compose.yaml.j2").read_text(encoding="utf-8")
    )
    assert template["networks"] == canonical_document["networks"]
    assert template["volumes"] == canonical_document["volumes"]
    assert template["services"]["web"]["command"] == ["serve", "--mode", "production"]
    assert template["services"]["web"]["depends_on"] == {
        "db": {"condition": "service_healthy"}
    }
    assert template["services"]["web"]["labels"] == {"org.example.component": "web"}
    assert template["services"]["db"]["healthcheck"] == {
        "test": ["CMD-SHELL", "pg_isready"]
    }


def test_generate_encrypts_remote_environment_secrets_without_plaintext_files(
    tmp_path: Path,
) -> None:
    """Classified remote environment values reach SOPS only over stdin."""
    secret_value = "remote-secret-must-not-persist"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: {secret_value}
      LOG_LEVEL: info
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value, "LOG_LEVEL": "info"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    sops_marker = tmp_path / "sops-marker"
    sops_arguments = tmp_path / "sops-arguments"
    _install_stub_command(
        bin_directory,
        "sops",
        """\
#!/bin/sh
payload=$(cat)
case "$payload" in
  *"$C2R_EXPECTED_SECRET"*)
    ;;
  *)
    exit 98
    ;;
esac
case "$*" in
  *"$C2R_EXPECTED_SECRET"*)
    exit 97
    ;;
esac
printf '%s\\n' "$@" > "$C2R_SOPS_ARGUMENTS"
printf '%s\\n' stdin-secret-received >> "$C2R_SOPS_MARKER"
cat <<'EOF'
sops:
  mac: ENC[AES256_GCM,data:fixture]
my_app_web_api_token: ENC[AES256_GCM,data:fixture]
EOF
""",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            **environment,
            "C2R_EXPECTED_SECRET": secret_value,
            "C2R_SOPS_ARGUMENTS": str(sops_arguments),
            "C2R_SOPS_MARKER": str(sops_marker),
        },
    )

    assert result.exit_code == 0, result.output
    role_directory = output_directory / "my_app"
    assert sops_marker.read_text(encoding="utf-8") == "stdin-secret-received\n"
    assert secret_value not in sops_arguments.read_text(encoding="utf-8")
    assert "--filename-override" in sops_arguments.read_text(encoding="utf-8")
    encrypted_secrets = (role_directory / "vars" / "secrets.sops.yml").read_text(
        encoding="utf-8"
    )
    assert "ENC[AES256_GCM,data:fixture]" in encrypted_secrets
    assert secret_value not in encrypted_secrets
    assert not (role_directory / ".sops.yaml").exists()
    assert not (role_directory / "vars" / "secrets.example.yml").exists()
    assert 'my_app_secrets_file: "{{ role_path }}/vars/secrets.sops.yml"' in (
        role_directory / "defaults" / "main.yml"
    ).read_text(encoding="utf-8")
    assert "community.sops.load_vars:" in (role_directory / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "community.sops" in (role_directory / "meta" / "requirements.yml").read_text(
        encoding="utf-8"
    )
    compose_template = (role_directory / "templates" / "compose.yaml.j2").read_text(
        encoding="utf-8"
    )
    assert "API_TOKEN: {{ my_app_secrets['my_app_web_api_token'] }}" in compose_template
    assert "LOG_LEVEL: {{ my_app_web_log_level }}" in compose_template
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret_value.encode("utf-8") not in path.read_bytes()
    assert secret_value not in result.output


def test_generated_remote_secret_role_passes_ansible_validation(tmp_path: Path) -> None:
    """The role wiring for encrypted remote environment values is lint- and syntax-valid."""
    secret_value = "ansible-validation-secret"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: {secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    _install_stub_command(
        bin_directory,
        "sops",
        """\
#!/bin/sh
cat >/dev/null
cat <<'EOF'
sops:
  mac: "ENC[AES256_GCM,data:fixture]"
my_app_web_api_token: "ENC[AES256_GCM,data:fixture]"
EOF
""",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    _assert_generated_role_validates(tmp_path, output_directory, "my_app")


def test_generate_writes_redacted_remote_provenance(tmp_path: Path) -> None:
    """Remote role provenance identifies structure without retaining environment values."""
    secret_value = "provenance-must-not-contain-this"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: {secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    _install_stub_command(
        bin_directory,
        "sops",
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$C2R_SOPS_OUTPUT\"\n",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            **environment,
            "C2R_SOPS_OUTPUT": _encrypted_sops_output("my_app_web_api_token"),
        },
    )

    assert result.exit_code == 0, result.output
    provenance_text = (output_directory / "my_app" / ".compose2role.json").read_text(
        encoding="utf-8"
    )
    provenance = json.loads(provenance_text)
    assert provenance["generator"] == "compose2role"
    assert provenance["mode"] == "remote"
    assert provenance["project"] == "my-app"
    assert provenance["role"] == "my_app"
    assert provenance["source"] == {
        "config_files": ["/srv/my-app/compose.yaml"],
        "root": "/srv/my-app",
    }
    assert len(provenance["structural_hash"]) == 64
    assert secret_value not in provenance_text


def test_remote_provenance_hash_is_stable_when_only_environment_values_change(
    tmp_path: Path,
) -> None:
    """Effective environment values do not influence the structural provenance hash."""
    hashes: list[str] = []
    for index, log_level in enumerate(("info", "debug"), start=1):
        case_directory = tmp_path / str(index)
        case_directory.mkdir()
        source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      LOG_LEVEL: {log_level}
"""
        canonical_document = {
            "services": {
                "web": {
                    "environment": {"LOG_LEVEL": log_level},
                    "healthcheck": {"test": ["CMD", "true"]},
                    "image": "ghcr.io/example/web:1.2.3",
                    "restart": "unless-stopped",
                    "user": "1000:1000",
                }
            }
        }
        environment, sops_config = _remote_environment(
            case_directory, source_document, canonical_document
        )
        output_directory = case_directory / "roles"

        result = CliRunner().invoke(
            main,
            [
                "generate",
                "--host",
                "web1",
                "--project",
                "my-app",
                "--output",
                str(output_directory),
                "--sops-config",
                str(sops_config),
            ],
            env=environment,
        )

        assert result.exit_code == 0, result.output
        provenance = json.loads(
            (output_directory / "my_app" / ".compose2role.json").read_text(encoding="utf-8")
        )
        hashes.append(provenance["structural_hash"])

    assert hashes[0] == hashes[1]


def test_generate_check_validates_remote_secrets_without_writing_or_encrypting(
    tmp_path: Path,
) -> None:
    """Remote check mode reaches validation but leaves no role or SOPS artifact behind."""
    secret_value = "check-mode-secret"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: {secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    sops_called = tmp_path / "sops-called"
    _install_stub_command(bin_directory, "sops", "#!/bin/sh\n: > \"$C2R_SOPS_CALLED\"\nexit 99\n")
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
            "--check",
        ],
        env={**environment, "C2R_SOPS_CALLED": str(sops_called)},
    )

    assert result.exit_code == 0, result.output
    assert "✓ my-app -> my_app (checked)" in result.output
    assert "  templates/compose.yaml.j2" in result.output
    assert secret_value not in result.output
    assert not output_directory.exists()
    assert not sops_called.exists()

    json_result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
            "--check",
            "--format",
            "json",
        ],
        env={**environment, "C2R_SOPS_CALLED": str(sops_called)},
    )

    assert json_result.exit_code == 0, json_result.output
    checked_project = json.loads(json_result.output)["projects"][0]
    assert checked_project["role"] == "my_app"
    assert "templates/compose.yaml.j2" in checked_project["files"]
    assert secret_value not in json_result.output
    assert not output_directory.exists()
    assert not sops_called.exists()


def test_generate_all_keeps_successful_roles_after_an_isolated_failure(tmp_path: Path) -> None:
    """Bulk generation keeps a good role when another project is not portable."""
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"bad","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/bad/compose.yaml"},'
  printf '%s\\n' '{"Name":"good","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/good/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    if [ "$path" = /srv/bad/compose.yaml ]; then
      printf '%s\\n' 'file 640 0 0'
      base64 <<'EOF' | tr -d '\\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
    build: .
EOF
    else
      printf '%s\\n' 'file 640 0 0'
      base64 <<'EOF' | tr -d '\\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
    fi
    printf '\\n'
    ;;
  stat)
    printf '%s\\n' missing
    ;;
  config)
    printf '%s\\n' '{"services":{"web":{"environment":{},'
    printf '%s\\n' '"healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"image":"ghcr.io/example/web:1.2.3",'
    printf '%s\\n' '"restart":"unless-stopped","user":"1000:1000"}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )
    _install_stub_command(bin_directory, "sops", "#!/bin/sh\nexit 99\n")
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--all",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
            "--format",
            "json",
        ],
        env={"PATH": f"{bin_directory}:{os.environ['PATH']}"},
    )

    assert result.exit_code == 1, result.output
    summary = json.loads(result.output)["projects"]
    assert [(project["name"], project["role"], project["status"]) for project in summary] == [
        ("bad", None, "failed"),
        ("good", "good", "generated"),
    ]
    assert summary[0]["error"] == "C2R005: remote build contexts are not supported"
    assert (output_directory / "good").is_dir()
    assert not (output_directory / "bad").exists()


def test_generate_all_adopts_multifile_sources_and_isolates_an_unsupported_project(
    tmp_path: Path,
) -> None:
    """Bulk generation retains a source-faithful role without persisting its secrets."""
    secret_value = "postgres://operator:bulk-source-secret@db/app"
    primary_source = (
        b"# Primary source remains byte-faithful.\r\n"
        b"services:\r\n"
        b"  web:\r\n"
        b"    image: ghcr.io/example/web:1.2.3\r\n"
        b"    environment:\r\n"
        b"      DATABASE_URL: ${DATABASE_URL}\r\n"
        b"    env_file: ./env/web.env\r\n"
        b"secrets:\r\n"
        b"  app_secret:\r\n"
        b"    file: ./secrets/app.bin\r\n"
    )
    override_source = b"""\
services:
  web:
    environment:
      LOG_LEVEL: debug
"""
    root_dotenv = f"DATABASE_URL={secret_value}\n".encode()
    service_dotenv = b"LOG_LEVEL=debug\n"
    file_secret = b"\x00bulk-file-secret\n"
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"good-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":["/srv/good/compose.yaml",'
  printf '%s\\n' '"/srv/good/compose.override.yaml"]},'
  printf '%s\\n' '{"Name":"bad-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/bad/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    printf '%s\\n' 'file 640 0 0'
    case "$path" in
      /srv/good/compose.yaml) printf '%s\\n' "$C2R_PRIMARY_SOURCE" ;;
      /srv/good/compose.override.yaml) printf '%s\\n' "$C2R_OVERRIDE_SOURCE" ;;
      /srv/good/.env) printf '%s\\n' "$C2R_ROOT_DOTENV" ;;
      /srv/good/env/web.env) printf '%s\\n' "$C2R_SERVICE_DOTENV" ;;
      /srv/good/secrets/app.bin) printf '%s\\n' "$C2R_FILE_SECRET" ;;
      /srv/bad/compose.yaml)
        base64 <<'EOF' | tr -d '\\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
    build: .
EOF
        printf '\\n'
        ;;
      *) exit 98 ;;
    esac
    ;;
  stat)
    case "$path" in
      /srv/good/.env|/srv/good/env/web.env|/srv/good/secrets/app.bin) printf '%s\\n' file ;;
      /srv/bad/.env) printf '%s\\n' missing ;;
      *) exit 98 ;;
    esac
    ;;
  config)
    printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
    ;;
  *) exit 97 ;;
esac
""",
    )
    _install_stub_command(
        bin_directory,
        "sops",
        """\
#!/bin/sh
printf '%s\\n' called >> "$C2R_SOPS_CALLS"
cat >/dev/null
printf '%s\\n' "$C2R_SOPS_OUTPUT"
""",
    )
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    canonical_document = {
        "services": {
            "web": {
                "environment": {"DATABASE_URL": secret_value, "LOG_LEVEL": "debug"},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    sops_calls = tmp_path / "sops-calls"
    output_directory = tmp_path / "roles"
    environment = {
        "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
        "C2R_FILE_SECRET": base64.b64encode(file_secret).decode("ascii"),
        "C2R_OVERRIDE_SOURCE": base64.b64encode(override_source).decode("ascii"),
        "C2R_PRIMARY_SOURCE": base64.b64encode(primary_source).decode("ascii"),
        "C2R_ROOT_DOTENV": base64.b64encode(root_dotenv).decode("ascii"),
        "C2R_SERVICE_DOTENV": base64.b64encode(service_dotenv).decode("ascii"),
        "C2R_SOPS_CALLS": str(sops_calls),
        "C2R_SOPS_OUTPUT": _encrypted_sops_output(
            "good_app_dotenv_env_database_url", "good_app_secret_app_secret"
        ),
        "PATH": f"{bin_directory}:{os.environ['PATH']}",
    }
    arguments = [
        "generate",
        "--host",
        "web1",
        "--all",
        "--output",
        str(output_directory),
        "--sops-config",
        str(sops_config),
        "--format",
        "json",
    ]

    result = CliRunner().invoke(main, arguments, env=environment)

    assert result.exit_code == 1, result.output
    summary = json.loads(result.output)["projects"]
    assert [(item["name"], item["role"], item["status"]) for item in summary] == [
        ("good-app", "good_app", "generated"),
        ("bad-app", None, "failed"),
    ]
    assert summary[1]["error"] == "C2R005: remote build contexts are not supported"
    assert secret_value not in result.output
    assert (output_directory / "good_app").is_dir()
    assert not (output_directory / "bad_app").exists()
    assert sops_calls.read_text(encoding="utf-8").splitlines() == ["called"]

    role_directory = output_directory / "good_app"
    defaults = YAML(typ="safe").load(
        (role_directory / "defaults" / "main.yml").read_text(encoding="utf-8")
    )
    assert isinstance(defaults, dict)
    for relative_path, source, newline_sequence in (
        ("compose.yaml", primary_source, "\r\n"),
        ("compose.override.yaml", override_source, "\n"),
        (".env", root_dotenv, "\n"),
        ("env/web.env", service_dotenv, "\n"),
    ):
        template = (role_directory / "templates" / f"{relative_path}.j2").read_text(
            encoding="utf-8"
        )
        rendered = Environment(
            keep_trailing_newline=True, newline_sequence=newline_sequence
        ).from_string(template).render(
            **defaults,
            good_app_secrets={"good_app_dotenv_env_database_url": secret_value},
        )
        assert rendered.encode() == source
    role_bytes = b"".join(
        path.read_bytes() for path in role_directory.rglob("*") if path.is_file()
    )
    assert secret_value.encode() not in role_bytes
    assert base64.b64encode(file_secret) not in role_bytes
    assert secret_value not in (role_directory / ".compose2role.json").read_text(encoding="utf-8")

    check_output = tmp_path / "check-roles"
    check_result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--all",
            "--output",
            str(check_output),
            "--sops-config",
            str(sops_config),
            "--check",
            "--format",
            "json",
        ],
        env=environment,
    )

    assert check_result.exit_code == 1, check_result.output
    checked_summary = json.loads(check_result.output)["projects"]
    assert [(item["name"], item["role"], item["status"]) for item in checked_summary] == [
        ("good-app", "good_app", "checked"),
        ("bad-app", None, "failed"),
    ]
    assert "templates/compose.yaml.j2" in checked_summary[0]["files"]
    assert secret_value not in check_result.output
    assert not check_output.exists()
    assert sops_calls.read_text(encoding="utf-8").splitlines() == ["called"]


def test_generate_reports_secret_role_output_failures_as_output_failures(tmp_path: Path) -> None:
    """A secret role's output failure is not misreported as an SOPS failure."""
    secret_value = "output-category-secret"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: {secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    _install_stub_command(
        bin_directory,
        "sops",
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$C2R_SOPS_OUTPUT\"\n",
    )
    output_directory = tmp_path / "roles"
    output_directory.write_text("not a directory", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={
            **environment,
            "C2R_SOPS_OUTPUT": _encrypted_sops_output("my_app_web_api_token"),
        },
    )

    assert result.exit_code == 1, result.output
    assert (
        "my-app -> my_app: FAILED (output): remote role output must be a directory"
        in result.output
    )
    assert secret_value not in result.output


def test_generate_keeps_secret_role_unwritten_when_sops_encryption_fails(tmp_path: Path) -> None:
    """SOPS failure exposes no stderr value and leaves no partial role behind."""
    secret_value = "sops-failure-secret"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: {secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    _install_stub_command(
        bin_directory,
        "sops",
        "#!/bin/sh\nprintf '%s\\n' \"$C2R_EXPECTED_SECRET\" >&2\nexit 91\n",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={**environment, "C2R_EXPECTED_SECRET": secret_value},
    )

    assert result.exit_code == 1, result.output
    assert "my-app -> my_app: FAILED (sops): SOPS encryption failed" in result.output
    assert secret_value not in result.output
    assert not output_directory.exists()


@pytest.mark.parametrize(
    "sops_output",
    (
        "not: [valid",
        "sops:\n  mac: ENC[AES256_GCM,data:fixture]",
        "my_app_web_api_token: sops-output-secret\nsops:\n  mac: ENC[AES256_GCM,data:fixture]",
    ),
    ids=("invalid-yaml", "missing-secret", "plaintext-secret"),
)
def test_generate_keeps_secret_role_unwritten_when_sops_output_is_invalid(
    tmp_path: Path, sops_output: str
) -> None:
    """Malformed, incomplete, or plaintext SOPS output never reaches a role directory."""
    secret_value = "sops-output-secret"
    source_document = f"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: {secret_value}
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {"API_TOKEN": secret_value},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    _install_stub_command(
        bin_directory,
        "sops",
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$C2R_SOPS_OUTPUT\"\n",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
        ],
        env={**environment, "C2R_SOPS_OUTPUT": sops_output},
    )

    assert result.exit_code == 1, result.output
    assert "my-app -> my_app: FAILED (sops): SOPS encryption output is invalid" in result.output
    assert secret_value not in result.output
    assert not output_directory.exists()


def test_generate_all_rejects_normalized_role_name_collisions_before_writing(
    tmp_path: Path,
) -> None:
    """Raw project names that normalize equally leave no ambiguous role output."""
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"my-app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/my-app/compose.yaml"},'
  printf '%s\\n' '{"Name":"my_app","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/my_app/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s\\n' 'file 640 0 0'
    base64 <<'EOF' | tr -d '\\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
    printf '\\n'
    ;;
  stat)
    printf '%s\\n' missing
    ;;
  config)
    printf '%s\\n' '{"services":{"web":{"environment":{},'
    printf '%s\\n' '"healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"image":"ghcr.io/example/web:1.2.3",'
    printf '%s\\n' '"restart":"unless-stopped","user":"1000:1000"}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )
    _install_stub_command(bin_directory, "sops", "#!/bin/sh\nexit 99\n")
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--all",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
            "--format",
            "json",
        ],
        env={"PATH": f"{bin_directory}:{os.environ['PATH']}"},
    )

    assert result.exit_code == 1, result.output
    projects = json.loads(result.output)["projects"]
    assert [(project["name"], project["role"], project["status"]) for project in projects] == [
        ("my-app", "my_app", "failed"),
        ("my_app", "my_app", "failed"),
    ]
    assert all(
        project["error"] == "normalized remote role name collides with another selected project"
        for project in projects
    )
    assert not output_directory.exists()


def test_generate_check_reports_planned_files_for_pre_existing_role_without_modifying_it(
    tmp_path: Path,
) -> None:
    """Check mode lists planned files without validating or altering existing output."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    output_directory = tmp_path / "roles"
    role_directory = output_directory / "my_app"
    role_directory.mkdir(parents=True)
    sentinel = role_directory / "operator-file"
    sentinel.write_text("do not alter", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
            "--check",
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    assert "my-app -> my_app (checked)" in result.output
    assert "  .compose2role.json" in result.output
    assert sentinel.read_text(encoding="utf-8") == "do not alter"
    assert not (role_directory / ".compose2role.json").exists()


def test_generate_check_rejects_a_symlinked_output_directory(tmp_path: Path) -> None:
    """Check mode applies the writer's output-directory safety rule before reporting success."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    target_directory = tmp_path / "operator-output"
    target_directory.mkdir()
    output_directory = tmp_path / "roles"
    output_directory.symlink_to(target_directory, target_is_directory=True)

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--sops-config",
            str(sops_config),
            "--check",
        ],
        env=environment,
    )

    assert result.exit_code == 1, result.output
    assert (
        "my-app -> my_app: FAILED (output): remote role output must be a directory"
        in result.output
    )
    assert not (target_directory / "my_app").exists()


def test_generate_prefers_explicit_sops_config_and_falls_back_to_environment(
    tmp_path: Path,
) -> None:
    """The selected SOPS config has deterministic option-over-environment precedence."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, explicit_config = _remote_environment(
        tmp_path, source_document, canonical_document
    )
    environment_config = tmp_path / "environment-sops.yaml"
    environment_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    missing_config = tmp_path / "not-used.yaml"

    explicit_result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(tmp_path / "explicit-roles"),
            "--sops-config",
            str(explicit_config),
            "--check",
        ],
        env={**environment, "COMPOSE2ROLE_SOPS_CONFIG": str(missing_config)},
    )
    environment_result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(tmp_path / "environment-roles"),
            "--check",
        ],
        env={**environment, "COMPOSE2ROLE_SOPS_CONFIG": str(environment_config)},
    )

    assert explicit_result.exit_code == 0, explicit_result.output
    assert environment_result.exit_code == 0, environment_result.output


def test_generate_rejects_missing_sops_config_before_remote_acquisition(tmp_path: Path) -> None:
    """Missing configuration stops before the SSH resolver can acquire remote values."""
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        "#!/bin/sh\n: > \"$C2R_SSH_MARKER\"\nexit 97\n",
    )
    ssh_marker = tmp_path / "ssh-called"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(tmp_path / "roles"),
        ],
        env={
            "C2R_SSH_MARKER": str(ssh_marker),
            "COMPOSE2ROLE_SOPS_CONFIG": "",
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 1
    assert "remote generation requires an existing SOPS config" in result.output
    assert not ssh_marker.exists()


def test_generate_rejects_missing_sops_executable_before_remote_acquisition(tmp_path: Path) -> None:
    """A valid config does not permit SSH acquisition when SOPS is unavailable."""
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        "#!/bin/sh\n: > \"$C2R_SSH_MARKER\"\nexit 97\n",
    )
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: vars/secrets\\.sops\\.yml$\n",
        encoding="utf-8",
    )
    ssh_marker = tmp_path / "ssh-called"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(tmp_path / "roles"),
            "--sops-config",
            str(sops_config),
        ],
        env={"C2R_SSH_MARKER": str(ssh_marker), "PATH": str(bin_directory)},
    )

    assert result.exit_code == 1
    assert "remote generation requires the SOPS executable" in result.output
    assert not ssh_marker.exists()


def test_generate_check_validates_the_sops_creation_rule_before_remote_acquisition(
    tmp_path: Path,
) -> None:
    """Check mode validates an applicable creation rule without running SOPS or SSH."""
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    _install_stub_command(
        bin_directory,
        "ssh",
        "#!/bin/sh\n: > \"$C2R_SSH_MARKER\"\nexit 97\n",
    )
    _install_stub_command(bin_directory, "sops", "#!/bin/sh\nexit 97\n")
    sops_config = tmp_path / "sops.yaml"
    sops_config.write_text(
        "creation_rules:\n  - path_regex: other-output\\.yml$\n",
        encoding="utf-8",
    )
    ssh_marker = tmp_path / "ssh-called"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(tmp_path / "roles"),
            "--sops-config",
            str(sops_config),
            "--check",
        ],
        env={"C2R_SSH_MARKER": str(ssh_marker), "PATH": str(bin_directory)},
    )

    assert result.exit_code == 1
    assert "SOPS config has no creation rule for vars/secrets.sops.yml" in result.output
    assert not ssh_marker.exists()


def test_generate_applies_secret_policy_overrides_to_remote_environment(
    tmp_path: Path,
) -> None:
    """Exact secret policy decisions override automatic remote environment classification."""
    source_document = """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: operator-approved-plain
      LOG_LEVEL: info
"""
    canonical_document = {
        "services": {
            "web": {
                "environment": {
                    "API_TOKEN": "operator-approved-plain",
                    "LOG_LEVEL": "info",
                },
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)
    bin_directory = Path(environment["PATH"].split(":", maxsplit=1)[0])
    _install_stub_command(
        bin_directory,
        "sops",
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$C2R_SOPS_OUTPUT\"\n",
    )
    secret_policy_path = tmp_path / "policy.toml"
    secret_policy_path.write_text(
        """\
[[rules]]
project = "my-app"
service = "web"
key = "API_TOKEN"
decision = "plain"

[[rules]]
project = "my-app"
service = "web"
key = "LOG_LEVEL"
decision = "secret"
""",
        encoding="utf-8",
    )
    output_directory = tmp_path / "roles"

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--project",
            "my-app",
            "--output",
            str(output_directory),
            "--secret-policy",
            str(secret_policy_path),
            "--sops-config",
            str(sops_config),
            "--format",
            "json",
        ],
        env={
            **environment,
            "C2R_SOPS_OUTPUT": _encrypted_sops_output("my_app_web_log_level"),
        },
    )

    assert result.exit_code == 0, result.output
    project = json.loads(result.output)["projects"][0]
    assert project["classifications"] == [
        {
            "key": "LOG_LEVEL",
            "location": "remote-compose.json:1:1",
            "reason": "secret-policy:forced-secret",
            "service": "web",
        }
    ]
    defaults = (output_directory / "my_app" / "defaults" / "main.yml").read_text(encoding="utf-8")
    compose_template = (output_directory / "my_app" / "templates" / "compose.yaml.j2").read_text(
        encoding="utf-8"
    )
    assert 'my_app_web_api_token: "operator-approved-plain"' in defaults
    assert "my_app_web_log_level:" not in defaults
    assert "API_TOKEN: {{ my_app_web_api_token }}" in compose_template
    assert "LOG_LEVEL: {{ my_app_secrets['my_app_web_log_level'] }}" in compose_template


def test_generate_refuses_other_nonportable_compose_features(tmp_path: Path) -> None:
    """Selected generation retains the resolver's build/extends/profiles/include refusals."""
    cases = (
        (
            "build",
            """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    build: .
""",
            "C2R005: remote build contexts are not supported",
        ),
        (
            "extends",
            """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    extends: base
""",
            "C2R006: remote service extends declarations are not supported",
        ),
        (
            "profiles",
            """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    profiles: [optional]
""",
            "C2R007: remote service profiles are not supported",
        ),
        (
            "include",
            """\
include: other.compose.yml
services:
  web:
    image: ghcr.io/example/web:1.2.3
""",
            "C2R008: remote Compose include files are not supported",
        ),
    )
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }

    for name, source_document, expected_message in cases:
        case_directory = tmp_path / name
        case_directory.mkdir()
        environment, sops_config = _remote_environment(
            case_directory, source_document, canonical_document
        )
        output_directory = case_directory / "roles"
        result = CliRunner().invoke(
            main,
            [
                "generate",
                "--host",
                "web1",
                "--project",
                "my-app",
                "--output",
                str(output_directory),
                "--sops-config",
                str(sops_config),
            ],
            env=environment,
        )

        assert result.exit_code == 1, result.output
        assert expected_message in result.output
        assert not output_directory.exists()


def test_generate_all_writes_roles_and_no_playbook(tmp_path: Path) -> None:
    """Generation is roles-only: --all writes one role per project and nothing else."""
    source_document = "services:\n  web:\n    image: ghcr.io/example/web:1.2.3\n"
    canonical_document = {
        "services": {
            "web": {
                "environment": {},
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }
    environment, sops_config = _remote_environment(tmp_path, source_document, canonical_document)

    result = CliRunner().invoke(
        main,
        [
            "generate",
            "--host",
            "web1",
            "--all",
            "--output",
            str(tmp_path / "roles"),
            "--sops-config",
            str(sops_config),
        ],
        env=environment,
    )

    assert result.exit_code == 0, result.output
    assert (tmp_path / "roles" / "my_app" / "tasks" / "main.yml").is_file()
    assert sorted(path.name for path in tmp_path.iterdir() if path.is_dir()) == [
        "bin",
        "roles",
    ]
