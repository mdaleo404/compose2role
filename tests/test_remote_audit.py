"""Remote audit behavior at the resolver and command-line seams."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath

import pytest
from click.testing import CliRunner
from ssh_stub import legacy_source_session_bridge

from compose2role.cli import main
from compose2role.remote import resolve_remote_projects


def _install_stub_ssh(tmp_path: Path, script: str, *, source_session: bool = False) -> Path:
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    ssh = bin_directory / "ssh"
    if source_session:
        ssh.write_text(script, encoding="utf-8")
        ssh.chmod(0o755)
        return bin_directory
    legacy_ssh = bin_directory / "ssh-legacy"
    legacy_ssh.write_text(script, encoding="utf-8")
    legacy_ssh.chmod(0o755)
    ssh.write_text(legacy_source_session_bridge(legacy_ssh), encoding="utf-8")
    ssh.chmod(0o755)
    return bin_directory


def _ssh_environment(bin_directory: Path, log_file: Path) -> dict[str, str]:
    return {
        "C2R_SSH_LOG": str(log_file),
        "PATH": f"{bin_directory}:{os.environ['PATH']}",
    }


_DRIFT_STUB = """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)","ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

if [ "$*" = '-- web1 sh -s' ]; then
  encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
  payload=$(printf '%s' "$encoded" | base64 -d)
  operation=$(printf '%s\\n' "$payload" | head -n 1)
  case "$operation" in
    capture)
      printf '%s\n' 'file 640 0 0'
      base64 <<'EOF' | tr -d '\n'
name: myapp
services:
  web:
    image: ghcr.io/example/web:IMAGE_TAG
EOF
      printf '\n'
      ;;
    stat)
      printf '%s\\n' 'missing'
      ;;
    config)
      printf '%s\\n' '{"name":"myapp","services":{"web":{"image":"ghcr.io/example/web:IMAGE_TAG"}}}'
      ;;
    *)
      exit 97
      ;;
  esac
  exit 0
fi

exit 97
"""


def _drift_stub(image_tag: str) -> str:
    return _DRIFT_STUB.replace("IMAGE_TAG", image_tag)


def test_audit_reports_remote_drift_and_all_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    source_text = """\
name: myapp
services:
  web:
    image: ghcr.io/example/web:1.2.3
"""
    role_directory = tmp_path / "roles" / "myapp"
    role_directory.mkdir(parents=True)
    (role_directory / ".compose2role.json").write_text(
        json.dumps(
            {
                "files": {
                    "compose.yaml": {
                        "sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest()
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    unchanged_root = tmp_path / "unchanged"
    unchanged_root.mkdir()
    unchanged_bin = _install_stub_ssh(unchanged_root, _drift_stub("1.2.3"))
    unchanged = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env=_ssh_environment(unchanged_bin, tmp_path / "unchanged-ssh-log"),
    )

    assert unchanged.exit_code == 0, unchanged.output
    assert json.loads(unchanged.output)["projects"][0]["drift"] == {
        "changed": [],
        "role": "myapp",
        "state": "unchanged",
    }

    changed_root = tmp_path / "changed"
    changed_root.mkdir()
    changed_bin = _install_stub_ssh(changed_root, _drift_stub("1.2.4"))
    changed = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--all", "--format", "json"],
        env=_ssh_environment(changed_bin, tmp_path / "changed-ssh-log"),
    )

    assert changed.exit_code == 0, changed.output
    assert json.loads(changed.output)["projects"][0]["drift"] == {
        "changed": ["compose.yaml"],
        "role": "myapp",
        "state": "source changed",
    }

    text_result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--all"],
        env=_ssh_environment(changed_bin, tmp_path / "text-ssh-log"),
    )

    assert text_result.exit_code == 0, text_result.output
    assert text_result.output.splitlines() == [
        "Discovering projects on web1...",
        "✓ myapp (source changed: compose.yaml)",
        "",
        "1 ok, 1 drift",
    ]


def test_audit_resolves_one_remote_project_without_exposing_source_paths_in_ssh_argv(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "ssh-log"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)
{
  printf '%s\\n' 'ARGV'
  printf '%s\\n' "$@"
  printf '%s\\n' 'STDIN'
  printf '%s\\n' "$request"
  printf '%s\\n' 'END'
} >> "$C2R_SSH_LOG"

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)","ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

if [ "$*" = '-- web1 sh -s' ]; then
  encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
  payload=$(printf '%s' "$encoded" | base64 -d)
  operation=$(printf '%s\\n' "$payload" | head -n 1)
  case "$operation" in
    capture)
      printf '%s\n' 'file 640 0 0'
      base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
      printf '\n'
      ;;
    stat)
      printf '%s\\n' 'missing'
      ;;
    config)
      printf '%s\\n' '{"services":{"web":{"image":"ghcr.io/example/web:1.2.3",'
      printf '%s\\n' '"user":"1000:1000","healthcheck":{"test":["CMD","true"]},'
      printf '%s\\n' '"restart":"unless-stopped","environment":{}}}}'
      ;;
    *)
      exit 97
      ;;
  esac
  exit 0
fi

exit 97
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env=_ssh_environment(bin_directory, log_file),
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "projects": [
            {
                "classifications": [],
                "drift": {
                    "changed": [],
                    "reason": "role has not been generated",
                    "role": "myapp",
                    "state": "missing",
                },
                "error": None,
                "findings": [],
                "name": "myapp",
                "role": None,
                "status": "ok",
            }
        ]
    }
    log = log_file.read_text(encoding="utf-8")
    assert "/srv/myapp/compose.yaml" not in log.split("STDIN", maxsplit=1)[0]
    assert "ARGV\n--\nweb1\nsh\n-s\nSTDIN" in log
    expected_payload = base64.b64encode(
        b"config\nmyapp\n/srv/myapp\n/srv/myapp/compose.yaml\n"
    ).decode("ascii")
    assert expected_payload in log


@pytest.mark.parametrize(
    ("label_output", "expected_root", "expected_error", "forbidden_label_value"),
    (
        ("myapp\t/srv/stacks/myapp\n", "/srv/stacks/myapp", None, None),
        ("", "/srv/stacks/myapp/compose", None, None),
        (
            "myapp\t/srv/stacks/myapp\nmyapp\t/srv/other\n",
            None,
            "remote Compose project has conflicting working-directory labels",
            "/srv/other",
        ),
        (
            "myapp\tsource/relative\n",
            None,
            "remote Compose project working directory must be absolute",
            "source/relative",
        ),
        (
            "myapp\t/srv/stacks/myapp/../other\n",
            None,
            "remote Compose project working directory escapes the project root",
            "/srv/stacks/myapp/../other",
        ),
    ),
    ids=("label", "fallback", "conflict", "relative", "escape"),
)
def test_audit_uses_the_labeled_compose_project_directory_when_available(
    tmp_path: Path,
    label_output: str,
    expected_root: str | None,
    expected_error: str | None,
    forbidden_label_value: str | None,
) -> None:
    """The reported Compose working directory controls remote config and source containment."""
    payload_log = tmp_path / "payload-log"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/stacks/myapp/compose/compose.yaml"}]'
  exit 0
fi

case "$*" in
  *"docker ps"*)
    printf '%s' "$C2R_LABEL_OUTPUT"
    exit 0
    ;;
esac

if [ "$*" = '-- web1 sh -s' ]; then
  encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
  payload=$(printf '%s' "$encoded" | base64 -d)
  printf '%s\\n' "$payload" >> "$C2R_PAYLOAD_LOG"
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
    *) exit 97 ;;
  esac
  exit 0
fi

exit 97
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp"],
        env={
            "C2R_LABEL_OUTPUT": label_output,
            "C2R_PAYLOAD_LOG": str(payload_log),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    if expected_error is not None:
        assert result.exit_code == 1, result.output
        assert expected_error in result.output
        assert forbidden_label_value is not None
        assert forbidden_label_value not in result.output
        assert not payload_log.exists()
        return

    assert result.exit_code == 0, result.output
    assert expected_root is not None
    payloads = payload_log.read_text(encoding="utf-8")
    assert f"capture\n/srv/stacks/myapp/compose/compose.yaml\n{expected_root}\n" in payloads
    assert f"config\nmyapp\n{expected_root}\n" in payloads


def test_audit_rejects_compose_files_outside_a_usable_labeled_root(tmp_path: Path) -> None:
    """A label root must contain the reported Compose files before any source is read."""
    operation_called = tmp_path / "operation-called"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/other/compose.yaml"}]'
  exit 0
fi

case "$*" in
  *"docker ps"*)
    printf 'myapp\\t/srv/stacks/myapp\\n'
    exit 0
    ;;
  *"sh -s")
    : > "$C2R_OPERATION_CALLED"
    exit 97
    ;;
esac

exit 97
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            "C2R_OPERATION_CALLED": str(operation_called),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 1, result.output
    project = json.loads(result.output)["projects"][0]
    assert project["error"] == "remote Compose file path escapes the project root"
    assert "/srv/other/compose.yaml" not in result.output
    assert not operation_called.exists()


def test_audit_batches_multifile_source_and_dependent_input_capture(tmp_path: Path) -> None:
    """One source session retains all inputs without one SSH operation per file."""
    source_calls = tmp_path / "source-calls"
    primary_source = b"""\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      DATABASE_URL: ${DATABASE_URL}
    env_file: env/web.env
secrets:
  app_secret:
    file: ./secrets/app.bin
"""
    override_source = b"""\
services:
  web:
    environment:
      LOG_LEVEL: debug
"""
    root_dotenv = b"DATABASE_URL=postgres://operator:batch-source-secret@db/app\n"
    service_dotenv = b"LOG_LEVEL=debug\n"
    file_secret = b"\x00batch-file-secret\n"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":["/srv/myapp/compose.yaml",'
  printf '%s\\n' '"/srv/myapp/compose.override.yaml"]}]'
  exit 0
fi

if [ "$*" = '-- web1 sh -s' ]; then
  IFS= read -r first_line || exit 97
  if [ "$first_line" = '# compose2role-source-session-v1' ]; then
    while IFS= read -r line; do
      [ "$line" = '# compose2role-source-session-ready' ] && break
    done
    IFS= read -r invocation || exit 97
    [ "$invocation" = main ] || exit 97
    printf '%s\\n' session >> "$C2R_SOURCE_CALLS"
    printf '%s\\n' ready
    while IFS= read -r header; do
      set -- $header
      [ "$#" -eq 3 ] || exit 97
      [ "$1" = request ] || exit 97
      request_id=$2
      operation=$3
      IFS= read -r path || exit 97
      IFS= read -r root || exit 97
      IFS= read -r trailer || exit 97
      [ "$trailer" = "end $request_id" ] || exit 97
      printf '%s %s\\n' "$operation" "$path" >> "$C2R_SOURCE_CALLS"
      case "$operation" in
        capture)
          printf 'result %s file 640 0 0\\n' "$request_id"
          case "$path" in
            /srv/myapp/compose.yaml) printf '%s\\n' "$C2R_PRIMARY_SOURCE" ;;
            /srv/myapp/compose.override.yaml) printf '%s\\n' "$C2R_OVERRIDE_SOURCE" ;;
            /srv/myapp/.env) printf '%s\\n' "$C2R_ROOT_DOTENV" ;;
            /srv/myapp/env/web.env) printf '%s\\n' "$C2R_SERVICE_DOTENV" ;;
            /srv/myapp/secrets/app.bin) printf '%s\\n' "$C2R_FILE_SECRET" ;;
            *) exit 98 ;;
          esac
          ;;
        stat)
          case "$path" in
            /srv/myapp/.env|/srv/myapp/env/web.env|/srv/myapp/secrets/app.bin)
              printf 'result %s file\\n' "$request_id"
              ;;
            *) exit 98 ;;
          esac
          ;;
        *) exit 97 ;;
      esac
      printf 'end %s\\n' "$request_id"
    done
    exit 0
  fi
  request=$( { printf '%s\\n' "$first_line"; cat; } )
  encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
  payload=$(printf '%s' "$encoded" | base64 -d)
  operation=$(printf '%s\\n' "$payload" | head -n 1)
  case "$operation" in
    batch)
      printf '%s\\n' "$payload" >> "$C2R_SOURCE_CALLS"
      count=$(printf '%s\\n' "$payload" | sed -n '2p')
      index=0
      while [ "$index" -lt "$count" ]; do
        line=$((4 + index * 3))
        path=$(printf '%s\\n' "$payload" | sed -n "${line}p")
        printf 'result %s file 640 0 0\\n' "$index"
        case "$path" in
          /srv/myapp/compose.yaml) printf '%s\\n' "$C2R_PRIMARY_SOURCE" ;;
          /srv/myapp/compose.override.yaml) printf '%s\\n' "$C2R_OVERRIDE_SOURCE" ;;
          /srv/myapp/.env) printf '%s\\n' "$C2R_ROOT_DOTENV" ;;
          /srv/myapp/env/web.env) printf '%s\\n' "$C2R_SERVICE_DOTENV" ;;
          /srv/myapp/secrets/app.bin) printf '%s\\n' "$C2R_FILE_SECRET" ;;
          *) exit 98 ;;
        esac
        index=$((index + 1))
      done
      ;;
    config)
      printf '%s\\n' "$C2R_CANONICAL_DOCUMENT"
      ;;
    *) exit 97 ;;
  esac
  exit 0
fi

exit 97
""",
        source_session=True,
    )
    canonical_document = {
        "services": {
            "web": {
                "environment": {
                    "DATABASE_URL": "postgres://operator:batch-source-secret@db/app",
                    "LOG_LEVEL": "debug",
                },
                "healthcheck": {"test": ["CMD", "true"]},
                "image": "ghcr.io/example/web:1.2.3",
                "restart": "unless-stopped",
                "user": "1000:1000",
            }
        }
    }

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            "C2R_CANONICAL_DOCUMENT": json.dumps(canonical_document),
            "C2R_FILE_SECRET": base64.b64encode(file_secret).decode("ascii"),
            "C2R_OVERRIDE_SOURCE": base64.b64encode(override_source).decode("ascii"),
            "C2R_PRIMARY_SOURCE": base64.b64encode(primary_source).decode("ascii"),
            "C2R_ROOT_DOTENV": base64.b64encode(root_dotenv).decode("ascii"),
            "C2R_SERVICE_DOTENV": base64.b64encode(service_dotenv).decode("ascii"),
            "C2R_SOURCE_CALLS": str(source_calls),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 0, result.output
    assert "batch-source-secret" not in result.output
    calls = source_calls.read_text(encoding="utf-8")
    assert calls.count("session\n") == 1
    assert "capture /srv/myapp/compose.yaml" in calls
    assert "capture /srv/myapp/compose.override.yaml" in calls
    assert "capture /srv/myapp/.env" in calls
    assert "capture /srv/myapp/env/web.env" in calls
    assert "capture /srv/myapp/secrets/app.bin" in calls


def test_audit_keeps_a_failed_source_session_request_value_free(tmp_path: Path) -> None:
    """A request error fails only its project after prior source requests succeeded."""
    secret_value = "session-request-secret-must-not-escape"
    source_calls = tmp_path / "source-calls"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

if [ "$*" = '-- web1 sh -s' ]; then
  IFS= read -r first_line || exit 97
  if [ "$first_line" = '# compose2role-source-session-v1' ]; then
    while IFS= read -r line; do
      [ "$line" = '# compose2role-source-session-ready' ] && break
    done
    IFS= read -r invocation || exit 97
    [ "$invocation" = main ] || exit 97
    printf '%s\\n' session >> "$C2R_SOURCE_CALLS"
    printf '%s\\n' ready
    while IFS= read -r header; do
      set -- $header
      request_id=$2
      operation=$3
      IFS= read -r path || exit 97
      IFS= read -r root || exit 97
      IFS= read -r trailer || exit 97
      [ "$trailer" = "end $request_id" ] || exit 97
      printf '%s %s\\n' "$operation" "$path" >> "$C2R_SOURCE_CALLS"
      case "$operation:$path" in
        capture:/srv/myapp/compose.yaml)
          printf 'result %s file 640 0 0\\n' "$request_id"
          base64 <<'EOF' | tr -d '\\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
    env_file: env/web.env
EOF
          printf '\\n'
          ;;
        stat:/srv/myapp/.env)
          printf 'result %s missing\\n' "$request_id"
          ;;
        stat:/srv/myapp/env/web.env)
          printf 'result %s error\\n' "$request_id"
          ;;
        *) exit 98 ;;
      esac
      printf 'end %s\\n' "$request_id"
    done
    exit 0
  fi
  printf '%s\\n' config >> "$C2R_SOURCE_CALLS"
  exit 98
fi

exit 97
""",
        source_session=True,
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            "C2R_SOURCE_CALLS": str(source_calls),
            "PATH": f"{bin_directory}:{os.environ['PATH']}",
        },
    )

    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["projects"][0]["error"] == "remote source request failed"
    assert secret_value not in result.output
    calls = source_calls.read_text(encoding="utf-8")
    assert calls.count("session\n") == 1
    assert "capture /srv/myapp/compose.yaml" in calls
    assert "stat /srv/myapp/.env" in calls
    assert "stat /srv/myapp/env/web.env" in calls
    assert "config\n" not in calls


def test_audit_reports_key_and_value_secret_classifications_without_values(tmp_path: Path) -> None:
    secret_value = "postgres://operator:never-print-this@db.example/app"
    log_file = tmp_path / "ssh-log"
    bin_directory = _install_stub_ssh(
        tmp_path,
        f"""\
#!/bin/sh
request=$(cat)
printf '%s\\n' "$request" >> "$C2R_SSH_LOG"

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}}]'
  exit 0
fi

if [ "$*" = '-- web1 sh -s' ]; then
  encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
  payload=$(printf '%s' "$encoded" | base64 -d)
  operation=$(printf '%s\\n' "$payload" | head -n 1)
  case "$operation" in
    capture)
      printf '%s\n' 'file 640 0 0'
      base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
      printf '\n'
      ;;
    stat)
      printf '%s\\n' 'missing'
      ;;
    config)
      printf '%s\\n' '{{"services":{{"web":{{"image":"ghcr.io/example/web:1.2.3",'
      printf '%s\\n' '"user":"1000:1000","healthcheck":{{"test":["CMD","true"]}},'
      printf '%s\\n' '"restart":"unless-stopped","environment":{{"API_TOKEN":"ordinary-looking",'
      printf '%s\\n' '"DATABASE_URL":"{secret_value}"}}}}}}}}'
      ;;
    *)
      exit 97
      ;;
  esac
  exit 0
fi

exit 97
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env=_ssh_environment(bin_directory, log_file),
    )

    assert result.exit_code == 0, result.output
    project = json.loads(result.output)["projects"][0]
    assert project["classifications"] == [
        {
            "key": "API_TOKEN",
            "location": "remote-compose.json:1:1",
            "reason": "key-name",
            "service": "web",
        },
        {
            "key": "DATABASE_URL",
            "location": "remote-compose.json:1:1",
            "reason": "value:credential-uri",
            "service": "web",
        },
    ]
    assert [finding["id"] for finding in project["findings"]] == ["C2R025", "C2R025"]
    assert secret_value not in result.output
    assert secret_value not in log_file.read_text(encoding="utf-8")

    text_result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--verbose"],
        env=_ssh_environment(bin_directory, tmp_path / "text-ssh-log"),
    )

    assert text_result.exit_code == 0, text_result.output
    assert text_result.output.splitlines() == [
        "Discovering projects on web1...",
        "✓ myapp (missing)",
        "  remote-compose.json:1:1: INFO C2R025: API_TOKEN is classified as a secret (key-name)",
        "  remote-compose.json:1:1: INFO C2R025: DATABASE_URL is classified as a secret "
        "(value:credential-uri)",
        "",
        "1 ok",
    ]
    assert secret_value not in text_result.output

    quiet_result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp"],
        env=_ssh_environment(bin_directory, tmp_path / "quiet-ssh-log"),
    )

    assert quiet_result.exit_code == 0, quiet_result.output
    assert "C2R025" not in quiet_result.output
    assert "✓ myapp" in quiet_result.output


def test_audit_resolves_ordered_compose_files_and_contained_environment_inputs(
    tmp_path: Path,
) -> None:
    payload_log = tmp_path / "ssh-payloads"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":["/srv/myapp/compose.yaml",'
  printf '%s\\n' '"/srv/myapp/compose.override.yaml"]}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
{
  printf '%s\\n' 'REQUEST'
  printf '%s\\n' "$payload"
  printf '%s\\n' 'END'
} >> "$C2R_SSH_PAYLOADS"
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')

case "$operation" in
  capture)
    case "$path" in
      /srv/myapp/compose.yaml)
        printf '%s\n' 'file 640 0 0'
        base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
    env_file: app.env
    environment:
      LOG_LEVEL: info
EOF
        ;;
      /srv/myapp/compose.override.yaml)
        printf '%s\n' 'file 640 0 0'
        base64 <<'EOF' | tr -d '\n'
services:
  web:
    environment:
      LOG_LEVEL: debug
EOF
        ;;
      /srv/myapp/.env)
        printf '%s\n' 'file 640 0 0'
        base64 <<'EOF' | tr -d '\n'
COMPOSE_PROJECT_NAME=myapp
EOF
        ;;
      /srv/myapp/app.env)
        printf '%s\n' 'file 640 0 0'
        base64 <<'EOF' | tr -d '\n'
APP_MODE=production
EOF
        ;;
      *)
        exit 98
        ;;
    esac
    printf '\n'
    ;;
  stat)
    case "$path" in
      /srv/myapp/.env|/srv/myapp/app.env)
        printf '%s\\n' 'file'
        ;;
      *)
        exit 98
        ;;
    esac
    ;;
  config)
    printf '%s\\n' '{"services":{"web":{"image":"ghcr.io/example/web:1.2.3",'
    printf '%s\\n' '"user":"1000:1000","healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"restart":"unless-stopped","environment":{"LOG_LEVEL":"debug"}}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_SSH_PAYLOADS": str(payload_log),
        },
    )

    assert result.exit_code == 0, result.output
    payloads = payload_log.read_text(encoding="utf-8")
    assert payloads.index("capture\n/srv/myapp/compose.yaml") < payloads.index(
        "capture\n/srv/myapp/compose.override.yaml"
    )
    assert "stat\n/srv/myapp/.env" in payloads
    assert "stat\n/srv/myapp/app.env" in payloads
    assert "capture\n/srv/myapp/.env" in payloads
    assert "capture\n/srv/myapp/app.env" in payloads
    assert "config\nmyapp\n/srv/myapp\n/srv/myapp/compose.yaml" in payloads
    assert "/srv/myapp/compose.override.yaml\nEND" in payloads


def test_remote_resolver_retains_an_ordered_source_snapshot_for_adoption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    primary_source = b"""\
# preserve this source marker\r
services:\r
  web:\r
    image: ghcr.io/example/web:1.2.3\r
    volumes:\r
      - /srv/web-data:/var/lib/web\r
secrets:\r
  app_secret:\r
    file: ./secret.txt\r
"""
    override_source = b"""\
# preserve the relative layout
services:
  web:
    environment:
      LOG_LEVEL: debug
"""
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":["/srv/myapp/docker-compose.yml",'
  printf '%s\\n' '"/srv/myapp/compose/override.yaml"]}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')

case "$operation" in
  capture)
    case "$path" in
      /srv/myapp/docker-compose.yml)
        printf '%s\\n' 'file 640 1000 1001'
        printf '%s\\n' "$C2R_PRIMARY_SOURCE"
        ;;
      /srv/myapp/compose/override.yaml)
        printf '%s\\n' 'file 644 1002 1003'
        printf '%s\\n' "$C2R_OVERRIDE_SOURCE"
        ;;
      /srv/myapp/secret.txt)
        printf '%s\\n' 'file 600 1004 1005'
        printf '%s\\n' "$C2R_SECRET_SOURCE"
        ;;
      *)
        exit 98
        ;;
    esac
    ;;
  stat)
    if [ "$path" = /srv/myapp/secret.txt ]; then
      printf '%s\\n' file
    else
      printf '%s\\n' missing
    fi
    ;;
  config)
    printf '%s\\n' '{"services":{"web":{"environment":{"LOG_LEVEL":"debug"},'
    printf '%s\\n' '"healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"image":"ghcr.io/example/web:1.2.3",'
    printf '%s\\n' '"restart":"unless-stopped","user":"1000:1000",'
    printf '%s\\n' '"volumes":[{"source":"/srv/web-data","target":"/var/lib/web",'
    printf '%s\\n' '"type":"bind"}]}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )
    monkeypatch.setenv("C2R_PRIMARY_SOURCE", base64.b64encode(primary_source).decode("ascii"))
    monkeypatch.setenv("C2R_OVERRIDE_SOURCE", base64.b64encode(override_source).decode("ascii"))
    monkeypatch.setenv("C2R_SECRET_SOURCE", base64.b64encode(b"captured-secret\n").decode("ascii"))
    monkeypatch.setenv("PATH", f"{bin_directory}:{os.environ['PATH']}")

    result = resolve_remote_projects(
        "web1",
        project_name="myapp",
        all_projects=False,
        use_sudo=False,
        secret_policy=None,
    )

    assert not result.failures
    project = result.projects[0]
    assert project.source.root == PurePosixPath("/srv/myapp")
    assert [source.relative_path for source in project.source.files] == [
        PurePosixPath("docker-compose.yml"),
        PurePosixPath("compose/override.yaml"),
    ]
    assert [source.content for source in project.source.files] == [primary_source, override_source]
    assert [
        (source.metadata.mode, source.metadata.uid, source.metadata.gid)
        for source in project.source.files
    ] == [(0o640, 1000, 1001), (0o644, 1002, 1003)]
    assert [secret.name for secret in project.source.file_secrets] == ["app_secret"]
    assert project.source.file_secrets[0].source.relative_path == PurePosixPath("secret.txt")
    assert project.source.file_secrets[0].source.content == b"captured-secret\n"
    assert (
        project.source.file_secrets[0].source.metadata.mode,
        project.source.file_secrets[0].source.metadata.uid,
        project.source.file_secrets[0].source.metadata.gid,
    ) == (0o600, 1004, 1005)
    assert "preserve this source marker" not in json.dumps(result.as_json())
    assert "preserve this source marker" not in repr(project)


def test_remote_resolver_round_trips_wrapped_source_bytes_through_the_capture_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    source_path = root / "compose.yaml"
    source_content = (
        b"# " + b"n" * 90 + b"\r\n"
        b"services:\r\n"
        b"  web:\r\n"
        b"    image: ghcr.io/example/web:1.2.3\r\n"
        b"    labels:\r\n"
        b"      description: " + b"n" * 120 + b"\r\n"
    )
    source_path.write_bytes(source_content)
    source_path.chmod(0o640)
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$1" = -- ] && [ "$2" = web1 ] && [ "$3" = docker ]; then
  printf '%s\\n' "$C2R_DISCOVERY_JSON"
  exit 0
fi
if [ "$1" = -- ] && [ "$2" = web1 ] && [ "$3" = sh ] && [ "$4" = -s ]; then
  shift 2
  exec "$@"
fi
exit 99
""",
        source_session=True,
    )
    docker = bin_directory / "docker"
    docker.write_text(
        """\
#!/bin/sh
printf '%s\\n' '{"services":{"web":{"environment":{},'
printf '%s\\n' '"healthcheck":{"test":["CMD","true"]},'
printf '%s\\n' '"image":"ghcr.io/example/web:1.2.3",'
printf '%s\\n' '"restart":"unless-stopped","user":"1000:1000"}}}'
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_directory}:{os.environ['PATH']}")
    monkeypatch.setenv(
        "C2R_DISCOVERY_JSON",
        json.dumps([{"Name": "myapp", "Status": "running(1)", "ConfigFiles": str(source_path)}]),
    )

    result = resolve_remote_projects(
        "web1",
        project_name="myapp",
        all_projects=False,
        use_sudo=False,
        secret_policy=None,
    )

    assert not result.failures
    captured_source = result.projects[0].source.files[0]
    assert captured_source.content == source_content
    assert captured_source.metadata.mode == 0o640


def test_audit_accepts_bind_mount_and_file_backed_secret_source_declarations(
    tmp_path: Path,
) -> None:
    source_marker = "source-content-must-not-be-reported"
    source_document = f"""\
# {source_marker}
services:
  web:
    image: ghcr.io/example/web:1.2.3
    volumes:
      - /srv/web-data:/var/lib/web
secrets:
  app_secret:
    file: ./secret.txt
"""
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    case "$path" in
      /srv/myapp/compose.yaml)
        printf '%s\\n' 'file 640 1000 1001'
        printf '%s\\n' "$C2R_SOURCE_DOCUMENT"
        ;;
      /srv/myapp/secret.txt)
        printf '%s\\n' 'file 600 1000 1001'
        printf '%s\\n' "$C2R_SECRET_SOURCE"
        ;;
      *) exit 98 ;;
    esac
    ;;
  stat)
    if [ "$path" = /srv/myapp/secret.txt ]; then
      printf '%s\\n' file
    else
      printf '%s\\n' missing
    fi
    ;;
  config)
    printf '%s\\n' '{"services":{"web":{"environment":{},'
    printf '%s\\n' '"healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"image":"ghcr.io/example/web:1.2.3",'
    printf '%s\\n' '"restart":"unless-stopped","user":"1000:1000",'
    printf '%s\\n' '"volumes":[{"source":"/srv/web-data","target":"/var/lib/web",'
    printf '%s\\n' '"type":"bind"}]}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_SOURCE_DOCUMENT": base64.b64encode(source_document.encode("utf-8")).decode(
                "ascii"
            ),
            "C2R_SECRET_SOURCE": base64.b64encode(b"audit-only-secret\n").decode("ascii"),
        },
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["projects"][0]["status"] == "ok"
    assert "C2R013" not in result.output
    assert "C2R028" not in result.output
    assert source_marker not in result.output


def test_audit_refuses_a_symlinked_compose_source_before_canonical_resolution(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "source.yaml"
    target.write_text("services: {}\n", encoding="utf-8")
    compose_path = root / "compose.yaml"
    compose_path.symlink_to(target)
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$1" = -- ] && [ "$2" = web1 ] && [ "$3" = docker ]; then
  printf '%s\\n' "$C2R_DISCOVERY_JSON"
  exit 0
fi
if [ "$1" = -- ] && [ "$2" = web1 ] && [ "$3" = sh ] && [ "$4" = -s ]; then
  shift 2
  exec "$@"
fi
exit 99
""",
        source_session=True,
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_DISCOVERY_JSON": json.dumps(
                [{"Name": "myapp", "Status": "running(1)", "ConfigFiles": str(compose_path)}]
            ),
        },
    )

    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["projects"][0]["error"] == (
        "remote Compose source file must not be a symlink"
    )


def test_audit_refuses_a_compose_source_with_a_parent_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (outside / "override.yaml").write_text("services: {}\n", encoding="utf-8")
    (root / "nested").symlink_to(outside, target_is_directory=True)
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$1" = -- ] && [ "$2" = web1 ] && [ "$3" = docker ]; then
  printf '%s\\n' "$C2R_DISCOVERY_JSON"
  exit 0
fi
if [ "$1" = -- ] && [ "$2" = web1 ] && [ "$3" = sh ] && [ "$4" = -s ]; then
  shift 2
  exec "$@"
fi
exit 99
""",
        source_session=True,
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_DISCOVERY_JSON": json.dumps(
                [
                    {
                        "Name": "myapp",
                        "Status": "running(1)",
                        "ConfigFiles": [
                            str(root / "compose.yaml"),
                            str(root / "nested" / "override.yaml"),
                        ],
                    }
                ]
            ),
        },
    )

    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["projects"][0]["error"] == (
        "remote Compose file path escapes the project root"
    )


def test_audit_refuses_compose_files_outside_the_discovered_source_root(tmp_path: Path) -> None:
    root = tmp_path / "project"
    remote_operation_called = tmp_path / "remote-operation-called"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' "$C2R_DISCOVERY_JSON"
  exit 0
fi
if [ "$*" = '-- web1 sh -s' ]; then
  : > "$C2R_REMOTE_OPERATION_CALLED"
fi
exit 99
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_DISCOVERY_JSON": json.dumps(
                [
                    {
                        "Name": "myapp",
                        "Status": "running(1)",
                        "ConfigFiles": [str(root / "compose.yaml"), "/etc/override.yaml"],
                    }
                ]
            ),
            "C2R_REMOTE_OPERATION_CALLED": str(remote_operation_called),
        },
    )

    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["projects"][0]["error"] == (
        "remote Compose file path escapes the project root"
    )
    assert not remote_operation_called.exists()


def test_audit_quarantines_invalid_source_metadata(tmp_path: Path) -> None:
    invalid_uid = "9" * 5_000
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf 'file 640 %s 0\\n' "$C2R_INVALID_UID"
    printf '%s\\n' "$C2R_SOURCE_DOCUMENT"
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_INVALID_UID": invalid_uid,
            "C2R_SOURCE_DOCUMENT": base64.b64encode(b"services: {}\n").decode("ascii"),
        },
    )

    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["projects"][0]["error"] == "remote source metadata is invalid"
    assert invalid_uid not in result.output


@pytest.mark.parametrize(
    ("capture_response", "expected_error", "unexposed_value"),
    (
        ("missing\n", "remote Compose source file is not a regular file", "missing"),
        ("other\n", "remote Compose source file is not a regular file", "other"),
        (
            "file 640 1000 1001\nnot-valid-base64-payload\n",
            "remote source content is invalid",
            "not-valid-base64-payload",
        ),
    ),
)
def test_audit_quarantines_invalid_capture_responses(
    tmp_path: Path,
    capture_response: str,
    expected_error: str,
    unexposed_value: str,
) -> None:
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s' "$C2R_CAPTURE_RESPONSE"
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_CAPTURE_RESPONSE": capture_response,
        },
    )

    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["projects"][0]["error"] == expected_error
    assert unexposed_value not in result.output


def test_audit_refuses_remote_build_sources_before_composing(tmp_path: Path) -> None:
    config_called = tmp_path / "config-called"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"unsafe","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/unsafe/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s\n' 'file 640 0 0'
    base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
    build: .
EOF
    printf '\n'
    ;;
  stat)
    printf '%s\\n' 'missing'
    ;;
  config)
    : > "$C2R_CONFIG_CALLED"
    printf '%s\\n' '{"services":{"web":{"image":"ghcr.io/example/web:1.2.3"}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "unsafe", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_CONFIG_CALLED": str(config_called),
        },
    )

    assert result.exit_code == 1, result.output
    project = json.loads(result.output)["projects"][0]
    assert project["status"] == "failed"
    assert project["error"] == "C2R005: remote build contexts are not supported"
    assert not config_called.exists()


def test_audit_secret_policy_overrides_automatic_secret_classification(tmp_path: Path) -> None:
    secret_policy_path = tmp_path / "policy.toml"
    secret_policy_path.write_text(
        """\
[[rules]]
project = "myapp"
service = "web"
key = "API_TOKEN"
decision = "plain"

[[rules]]
project = "myapp"
service = "web"
key = "LOG_LEVEL"
decision = "secret"
""",
        encoding="utf-8",
    )
    environment_secret_policy_path = tmp_path / "environment-secret-policy.toml"
    environment_secret_policy_path.write_text(
        """\
[[rules]]
project = "myapp"
service = "web"
key = "API_TOKEN"
decision = "secret"

[[rules]]
project = "myapp"
service = "web"
key = "LOG_LEVEL"
decision = "plain"
""",
        encoding="utf-8",
    )
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s\n' 'file 640 0 0'
    base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
    printf '\n'
    ;;
  stat)
    printf '%s\\n' 'missing'
    ;;
  config)
    printf '%s\\n' '{"services":{"web":{"image":"ghcr.io/example/web:1.2.3",'
    printf '%s\\n' '"user":"1000:1000","healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"restart":"unless-stopped","environment":{'
    printf '%s\\n' '"API_TOKEN":"automatic-secret","LOG_LEVEL":"info"}}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        [
            "audit",
            "--host",
            "web1",
            "--project",
            "myapp",
            "--secret-policy",
            str(secret_policy_path),
            "--format",
            "json",
        ],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "COMPOSE2ROLE_SECRET_POLICY": str(environment_secret_policy_path),
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
    assert [finding["message"] for finding in project["findings"]] == [
        "LOG_LEVEL is classified as a secret (secret-policy:forced-secret)"
    ]

    fallback_result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "fallback-ssh-log"),
            "COMPOSE2ROLE_SECRET_POLICY": str(environment_secret_policy_path),
        },
    )

    assert fallback_result.exit_code == 0, fallback_result.output
    fallback_classifications = json.loads(fallback_result.output)["projects"][0]["classifications"]
    assert [(item["key"], item["reason"]) for item in fallback_classifications] == [
        ("API_TOKEN", "secret-policy:forced-secret"),
    ]


def test_audit_rejects_conflicting_secret_policy_rules_before_remote_discovery(
    tmp_path: Path,
) -> None:
    secret_policy_path = tmp_path / "conflicting-secret-policy.toml"
    secret_policy_path.write_text(
        """\
[[rules]]
project = "myapp"
service = "web"
key = "API_TOKEN"
decision = "secret"

[[rules]]
project = "myapp"
service = "web"
key = "API_TOKEN"
decision = "plain"
""",
        encoding="utf-8",
    )
    ssh_log = tmp_path / "ssh-log"
    bin_directory = _install_stub_ssh(
        tmp_path,
        "#!/bin/sh\nprintf '%s\\n' invoked >> \"$C2R_SSH_LOG\"\nexit 99\n",
    )

    result = CliRunner().invoke(
        main,
        [
            "audit",
            "--host",
            "web1",
            "--project",
            "myapp",
            "--secret-policy",
            str(secret_policy_path),
        ],
        env=_ssh_environment(bin_directory, ssh_log),
    )

    assert result.exit_code == 1
    assert "secret policy has conflicting exact rules" in result.output
    assert not ssh_log.exists()


def test_audit_rejects_nonstring_secret_policy_decisions_without_remote_discovery(
    tmp_path: Path,
) -> None:
    secret_policy_path = tmp_path / "invalid-secret-policy.toml"
    secret_policy_path.write_text(
        """\
[[rules]]
project = "myapp"
service = "web"
key = "API_TOKEN"
decision = ["secret"]
""",
        encoding="utf-8",
    )
    ssh_log = tmp_path / "ssh-log"
    bin_directory = _install_stub_ssh(
        tmp_path,
        "#!/bin/sh\nprintf '%s\\n' invoked >> \"$C2R_SSH_LOG\"\nexit 99\n",
    )

    result = CliRunner().invoke(
        main,
        [
            "audit",
            "--host",
            "web1",
            "--project",
            "myapp",
            "--secret-policy",
            str(secret_policy_path),
        ],
        env=_ssh_environment(bin_directory, ssh_log),
    )

    assert result.exit_code == 1
    assert "secret policy rules are invalid" in result.output
    assert not ssh_log.exists()


def test_audit_reports_high_confidence_value_secret_signals(tmp_path: Path) -> None:
    private_key = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signaturetoken"
    token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234567890"
    long_token = "Abcdefghijklmnopqrstuvwxyz1234567890Z"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s\n' 'file 640 0 0'
    base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
    printf '\n'
    ;;
  stat)
    printf '%s\\n' 'missing'
    ;;
  config)
    printf '%s\\n' '{"services":{"web":{"image":"ghcr.io/example/web:1.2.3",'
    printf '%s\\n' '"user":"1000:1000","healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"restart":"unless-stopped","environment":{'
    printf '%s\\n' '"TLS_MATERIAL":"-----BEGIN PRIVATE KEY-----\\nnot-a-real-key",'
    printf '%s\\n' '"JWT_MATERIAL":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signaturetoken",'
    printf '%s\\n' '"CLIENT_ID":"ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234567890",'
    printf '%s\\n' '"OPAQUE_MATERIAL":"Abcdefghijklmnopqrstuvwxyz1234567890Z"}}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env=_ssh_environment(bin_directory, tmp_path / "ssh-log"),
    )

    assert result.exit_code == 0, result.output
    classifications = json.loads(result.output)["projects"][0]["classifications"]
    assert [(item["key"], item["reason"]) for item in classifications] == [
        ("TLS_MATERIAL", "value:private-key"),
        ("JWT_MATERIAL", "value:jwt"),
        ("CLIENT_ID", "value:opaque-token"),
        ("OPAQUE_MATERIAL", "value:opaque-token"),
    ]
    assert private_key not in result.output
    assert jwt not in result.output
    assert token not in result.output
    assert long_token not in result.output


def test_audit_all_keeps_successful_projects_when_another_project_fails(tmp_path: Path) -> None:
    bin_directory = _install_stub_ssh(
        tmp_path,
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
    case "$path" in
      /srv/bad/compose.yaml)
        printf '%s\n' 'file 640 0 0'
        base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
    build: .
EOF
        ;;
      /srv/good/compose.yaml)
        printf '%s\n' 'file 640 0 0'
        base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
        ;;
      *)
        exit 98
        ;;
    esac
    printf '\n'
    ;;
  stat)
    printf '%s\\n' 'missing'
    ;;
  config)
    printf '%s\\n' '{"services":{"web":{"image":"ghcr.io/example/web:1.2.3",'
    printf '%s\\n' '"user":"1000:1000","healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"restart":"unless-stopped","environment":{}}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--all", "--format", "json"],
        env=_ssh_environment(bin_directory, tmp_path / "ssh-log"),
    )

    assert result.exit_code == 1, result.output
    projects = json.loads(result.output)["projects"]
    assert [(project["name"], project["status"]) for project in projects] == [
        ("bad", "failed"),
        ("good", "ok"),
    ]
    assert projects[0]["error"] == "C2R005: remote build contexts are not supported"

    text_result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--all"],
        env=_ssh_environment(bin_directory, tmp_path / "text-ssh-log"),
    )

    assert text_result.exit_code == 1, text_result.output
    assert text_result.output.splitlines() == [
        "Discovering projects on web1...",
        "✗ bad: FAILED (source): C2R005: remote build contexts are not supported",
        "✓ good (missing)",
        "",
        "1 ok, 1 failed",
    ]


def test_audit_all_reports_an_empty_discovery_batch(tmp_path: Path) -> None:
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[]'
  exit 0
fi
exit 99
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--all", "--format", "json"],
        env=_ssh_environment(bin_directory, tmp_path / "ssh-log"),
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"projects": []}


def test_audit_reports_an_unknown_remote_project_without_resolving_source(tmp_path: Path) -> None:
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"known","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/known/compose.yaml"}]'
  exit 0
fi
exit 97
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "missing", "--format", "json"],
        env=_ssh_environment(bin_directory, tmp_path / "ssh-log"),
    )

    assert result.exit_code == 1, result.output
    assert json.loads(result.output) == {
        "projects": [
            {
                "classifications": [],
                "drift": None,
                "error": "the requested remote Compose project was not discovered",
                "findings": [],
                "name": "missing",
                "role": None,
                "status": "failed",
            }
        ]
    }


@pytest.mark.parametrize(
    ("failure_mode", "expected_error"),
    (
        ("ssh", "SSH connection or remote command failed"),
        ("compose", "remote Compose resolution failed for project 'myapp'"),
    ),
)
def test_audit_quarantines_ssh_and_remote_compose_error_output(
    tmp_path: Path, failure_mode: str, expected_error: str
) -> None:
    secret_value = "remote-error-value-must-not-print"
    bin_directory = _install_stub_ssh(
        tmp_path,
        f"""\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}}]'
  exit 0
fi

if [ "{failure_mode}" = ssh ]; then
  printf '%s\\n' '{secret_value}' >&2
  exit 255
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s\n' 'file 640 0 0'
    base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
    printf '\n'
    ;;
  stat)
    printf '%s\\n' 'missing'
    ;;
  config)
    printf '%s\\n' '{secret_value}' >&2
    exit 1
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env=_ssh_environment(bin_directory, tmp_path / "ssh-log"),
    )

    assert result.exit_code == 1, result.output
    project = json.loads(result.output)["projects"][0]
    assert project["error"] == expected_error
    assert secret_value not in result.output


def test_audit_quarantines_discovery_error_output(tmp_path: Path) -> None:
    secret_value = "discovery-error-value-must-not-print"
    bin_directory = _install_stub_ssh(
        tmp_path,
        f"#!/bin/sh\nprintf '%s\\n' '{secret_value}' >&2\nexit 255\n",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp"],
        env=_ssh_environment(bin_directory, tmp_path / "ssh-log"),
    )

    assert result.exit_code == 1
    assert "SSH discovery failed" in result.output
    assert secret_value not in result.output


def test_audit_rejects_control_characters_in_discovered_project_identity(tmp_path: Path) -> None:
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"bad\\nproject","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/bad/compose.yaml"}]'
  exit 0
fi
exit 99
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--all"],
        env=_ssh_environment(bin_directory, tmp_path / "ssh-log"),
    )

    assert result.exit_code == 1
    assert "remote Docker Compose discovery returned invalid project data" in result.output
    assert "bad" not in result.output


def test_audit_keeps_remote_plaintext_only_in_memory(tmp_path: Path) -> None:
    secret_value = "quarantine-value-must-not-persist"
    capture_file = tmp_path / "ssh-capture"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)
printf '%s\\n' "$request" >> "$C2R_SSH_CAPTURE"

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s\n' 'file 640 0 0'
    base64 <<EOF | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
    environment:
      API_TOKEN: $C2R_REMOTE_SECRET
EOF
    printf '\n'
    ;;
  stat)
    printf '%s\\n' 'missing'
    ;;
  config)
    printf '%s' '{"services":{"web":{"image":"ghcr.io/example/web:1.2.3",'
    printf '%s' '"user":"1000:1000","healthcheck":{"test":["CMD","true"]},'
    printf '%s' '"restart":"unless-stopped","environment":{"API_TOKEN":"'
    printf '%s' "$C2R_REMOTE_SECRET"
    printf '%s\\n' '"}}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_REMOTE_SECRET": secret_value,
            "C2R_SSH_CAPTURE": str(capture_file),
        },
    )

    assert result.exit_code == 0, result.output
    assert secret_value not in result.output
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert secret_value.encode("utf-8") not in path.read_bytes()


@pytest.mark.parametrize("effective_value", ("null", '"${FROM_HOST}"', '"$FROM_HOST"'))
def test_audit_rejects_inherited_or_unresolved_effective_environment(
    tmp_path: Path, effective_value: str
) -> None:
    closing = "}}}}"
    bin_directory = _install_stub_ssh(
        tmp_path,
        f"""\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s\n' 'file 640 0 0'
    base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
    printf '\n'
    ;;
  stat)
    printf '%s\\n' 'missing'
    ;;
  config)
    printf '%s' '{{"services":{{"web":{{"image":"ghcr.io/example/web:1.2.3",'
    printf '%s' '"user":"1000:1000","healthcheck":{{"test":["CMD","true"]}},'
    printf '%s' '"restart":"unless-stopped","environment":{{"FROM_HOST":'
    printf '%s\\n' '{effective_value}{closing}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env=_ssh_environment(bin_directory, tmp_path / "ssh-log"),
    )

    assert result.exit_code == 1, result.output
    project = json.loads(result.output)["projects"][0]
    assert project["error"] == "remote Docker Compose returned an unsupported effective model"
    assert "FROM_HOST" not in result.output


def test_audit_all_applies_fail_on_to_aggregated_remote_findings(tmp_path: Path) -> None:
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"warn","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/warn/compose.yaml"},'
  printf '%s\\n' '{"Name":"clean","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/clean/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
project=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    printf '%s\n' 'file 640 0 0'
    base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
    printf '\n'
    ;;
  stat)
    printf '%s\\n' 'missing'
    ;;
  config)
    if [ "$project" = warn ]; then
      printf '%s\\n' '{"services":{"web":{"image":"ghcr.io/example/web",'
    else
      printf '%s\\n' '{"services":{"web":{"image":"ghcr.io/example/web:1.2.3",'
    fi
    printf '%s\\n' '"user":"1000:1000","healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"restart":"unless-stopped","environment":{}}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        [
            "audit",
            "--host",
            "web1",
            "--all",
            "--format",
            "json",
            "--fail-on",
            "warning",
        ],
        env=_ssh_environment(bin_directory, tmp_path / "ssh-log"),
    )

    assert result.exit_code == 3, result.output
    projects = json.loads(result.output)["projects"]
    assert [project["name"] for project in projects] == ["warn", "clean"]
    assert projects[0]["findings"][0]["id"] == "C2R001"

    error_result = CliRunner().invoke(
        main,
        [
            "audit",
            "--host",
            "web1",
            "--all",
            "--format",
            "json",
            "--fail-on",
            "error",
        ],
        env=_ssh_environment(bin_directory, tmp_path / "error-ssh-log"),
    )

    assert error_result.exit_code == 0, error_result.output


@pytest.mark.parametrize(
    ("env_file", "state", "expected_error"),
    (
        (
            "/etc/remote.env",
            "missing",
            "remote environment file path escapes the project root",
        ),
        (
            "../outside.env",
            "missing",
            "remote environment file path escapes the project root",
        ),
        (
            "linked.env",
            "symlink",
            "remote service env_file input is not a regular file",
        ),
        (
            "missing.env",
            "missing",
            "remote service env_file input is not a regular file",
        ),
        (
            "nested/linked.env",
            "escape",
            "remote environment file path escapes the project root",
        ),
    ),
)
def test_audit_refuses_environment_inputs_outside_or_linked_from_project_root(
    tmp_path: Path,
    env_file: str,
    state: str,
    expected_error: str,
) -> None:
    config_called = tmp_path / "config-called"
    bin_directory = _install_stub_ssh(
        tmp_path,
        f"""\
#!/bin/sh
request=$(cat)

if [ "$*" = '-- web1 docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
path=$(printf '%s\\n' "$payload" | sed -n '2p')
case "$operation" in
  capture)
    printf '%s\n' 'file 640 0 0'
    base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
    env_file: {env_file}
EOF
    printf '\n'
    ;;
  stat)
    if [ "$path" = /srv/myapp/.env ]; then
      printf '%s\\n' 'missing'
    else
      printf '%s\\n' '{state}'
    fi
    ;;
  config)
    : > "$C2R_CONFIG_CALLED"
    exit 99
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_CONFIG_CALLED": str(config_called),
        },
    )

    assert result.exit_code == 1, result.output
    project = json.loads(result.output)["projects"][0]
    assert project["error"] == expected_error
    assert not config_called.exists()


def test_audit_rejects_parent_symlink_escape_from_a_glob_named_root(tmp_path: Path) -> None:
    root = tmp_path / "my[ab]"
    root.mkdir()
    outside = tmp_path / "mya"
    outside.mkdir()
    (outside / "linked.env").write_text("LOG_LEVEL=debug\n", encoding="utf-8")
    (root / "nested").symlink_to(outside, target_is_directory=True)
    compose_path = root / "compose.yaml"
    compose_path.write_text(
        """\
services:
  web:
    image: ghcr.io/example/web:1.2.3
    env_file: nested/linked.env
""",
        encoding="utf-8",
    )
    docker_called = tmp_path / "docker-called"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
if [ "$1" = -- ] && [ "$2" = web1 ] && [ "$3" = docker ]; then
  printf '%s\\n' "$C2R_DISCOVERY_JSON"
  exit 0
fi
if [ "$1" = -- ] && [ "$2" = web1 ] && [ "$3" = sh ] && [ "$4" = -s ]; then
  shift 2
  exec "$@"
fi
exit 99
""",
        source_session=True,
    )
    docker = bin_directory / "docker"
    docker.write_text(
        """\
#!/bin/sh
: > "$C2R_DOCKER_CALLED"
printf '%s\\n' "$C2R_CANONICAL_JSON"
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--project", "myapp", "--format", "json"],
        env={
            **_ssh_environment(bin_directory, tmp_path / "ssh-log"),
            "C2R_CONFIG_PATH": str(compose_path),
            "C2R_DISCOVERY_JSON": json.dumps(
                [{"Name": "myapp", "Status": "running(1)", "ConfigFiles": str(compose_path)}]
            ),
            "C2R_DOCKER_CALLED": str(docker_called),
            "C2R_CANONICAL_JSON": json.dumps(
                {
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
            ),
        },
    )

    assert result.exit_code == 1, result.output
    project = json.loads(result.output)["projects"][0]
    assert project["error"] == "remote environment file path escapes the project root"
    assert not docker_called.exists()


def test_audit_uses_noninteractive_sudo_for_every_remote_operation(tmp_path: Path) -> None:
    log_file = tmp_path / "ssh-log"
    bin_directory = _install_stub_ssh(
        tmp_path,
        """\
#!/bin/sh
request=$(cat)
{
  printf '%s\\n' 'ARGV'
  printf '%s\\n' "$@"
  printf '%s\\n' 'END'
} >> "$C2R_SSH_LOG"

if [ "$*" = '-- web1 sudo -n docker compose ls --all --format json' ]; then
  printf '%s\\n' '[{"Name":"myapp","Status":"running(1)",'
  printf '%s\\n' '"ConfigFiles":"/srv/myapp/compose.yaml"}]'
  exit 0
fi

encoded=$(printf '%s\\n' "$request" | tail -n 2 | head -n 1)
payload=$(printf '%s' "$encoded" | base64 -d)
operation=$(printf '%s\\n' "$payload" | head -n 1)
case "$operation" in
  capture)
    printf '%s\n' 'file 640 0 0'
    base64 <<'EOF' | tr -d '\n'
services:
  web:
    image: ghcr.io/example/web:1.2.3
EOF
    printf '\n'
    ;;
  stat)
    printf '%s\\n' 'missing'
    ;;
  config)
    printf '%s\\n' '{"services":{"web":{"image":"ghcr.io/example/web:1.2.3",'
    printf '%s\\n' '"user":"1000:1000","healthcheck":{"test":["CMD","true"]},'
    printf '%s\\n' '"restart":"unless-stopped","environment":{}}}}'
    ;;
  *)
    exit 97
    ;;
esac
""",
    )

    result = CliRunner().invoke(
        main,
        ["audit", "--host", "web1", "--sudo", "--project", "myapp", "--format", "json"],
        env=_ssh_environment(bin_directory, log_file),
    )

    assert result.exit_code == 0, result.output
    log = log_file.read_text(encoding="utf-8")
    assert "ARGV\n--\nweb1\nsudo\n-n\ndocker\ncompose\nls\n--all\n--format\njson" in log
    assert log.count("ARGV\n--\nweb1\nsudo\n-n\nsh\n-s\nEND") == 3
    assert "StrictHostKeyChecking" not in log


@pytest.mark.parametrize(
    "arguments",
    (
        ["audit", "--host", "web1"],
        ["audit", "--host", "web1", "--project", "myapp", "--all"],
    ),
)
def test_audit_requires_one_remote_selection(
    tmp_path: Path, arguments: list[str]
) -> None:
    ssh_log = tmp_path / "ssh-log"
    bin_directory = _install_stub_ssh(
        tmp_path,
        "#!/bin/sh\nprintf '%s\\n' invoked >> \"$C2R_SSH_LOG\"\nexit 99\n",
    )

    result = CliRunner().invoke(
        main,
        arguments,
        env=_ssh_environment(bin_directory, ssh_log),
    )

    assert result.exit_code == 2, result.output
    assert not ssh_log.exists()
