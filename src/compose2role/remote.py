"""Resolve remote Docker Compose projects without persisting their source data."""

from __future__ import annotations

import base64
import binascii
import json
import os
import shlex
from collections.abc import Callable
from json import JSONDecodeError
from pathlib import PurePosixPath
from select import select
from subprocess import DEVNULL, PIPE, Popen, TimeoutExpired, run
from time import monotonic
from typing import IO, NoReturn

from compose2role.discover import DiscoveredProject, discover_projects, ssh_command
from compose2role.errors import RemoteCommandError
from compose2role.resolve import (
    AuditOutcome,
    AuditResult,
    Canonicalizer,
    CanonicalResult,
    ProjectCapture,
    ProjectFailure,
    ProjectResolutionError,
    ResolvedProject,
    SourceFile,
    relative_source_path,
    resolve_project,
)
from compose2role.secret_policy import SecretPolicy
from compose2role.source import FileMetadata

_SSH_TIMEOUT_SECONDS = 30
_DISCOVERY_MESSAGES = {
    "ssh": "SSH discovery failed",
    "ssh-client": "OpenSSH client executable 'ssh' was not found",
    "ssh-timeout": "SSH discovery timed out",
    "remote-discovery": "remote Docker Compose discovery failed",
    "invalid-json": "remote Docker Compose discovery returned invalid JSON",
    "invalid-discovery": "remote Docker Compose discovery returned invalid project data",
}
_REMOTE_OPERATION_PREFIX = """\
set -eu
main() {
    base64 -d | {
        IFS= read -r operation || exit 64
        case "$operation" in
            config)
                IFS= read -r project || exit 64
                IFS= read -r root || exit 64
                set --
                while IFS= read -r file; do
                    [ -n "$file" ] || exit 64
                    set -- "$@" -f "$file"
                done
                exec env -i PATH="$PATH" %(docker)s compose --project-name "$project" \\
                    --project-directory "$root" "$@" config --format json
                ;;
            *)
                exit 64
                ;;
        esac
    }
}
main <<'__C2R_PAYLOAD__'
"""
_REMOTE_OPERATION_SUFFIX = """\
__C2R_PAYLOAD__
"""
_REMOTE_SOURCE_SESSION_SCRIPT = """\
# compose2role-source-session-v1
set -eu
source_state() {
    source_path=$1
    source_root=$2
    root_physical=$(CDPATH= cd -P "$source_root" && pwd -P) || return 65
    parent_physical=$(CDPATH= cd -P "$(dirname "$source_path")" && pwd -P) || parent_physical=
    if [ "$root_physical" != / ] && [ -n "$parent_physical" ] \
        && [ "$parent_physical" != "$root_physical" ] \
        && [ "${parent_physical#"$root_physical"/}" = "$parent_physical" ]; then
        printf '%s\\n' escape
    elif [ -L "$source_path" ]; then
        printf '%s\\n' symlink
    elif [ -f "$source_path" ]; then
        printf '%s\\n' file
    elif [ -e "$source_path" ]; then
        printf '%s\\n' other
    else
        printf '%s\\n' missing
    fi
}
main() {
    printf '%s\\n' ready
    while IFS=' ' read -r marker request_id request_operation extra; do
        [ "$marker" = request ] || exit 64
        [ -n "$request_id" ] && [ -z "$extra" ] || exit 64
        case "$request_id" in
            ''|*[!0-9]*) exit 64 ;;
        esac
        IFS= read -r path || exit 64
        IFS= read -r root || exit 64
        IFS= read -r trailer || exit 64
        [ "$trailer" = "end $request_id" ] || exit 64
        if ! state=$(source_state "$path" "$root"); then
            printf 'result %s error\\nend %s\\n' "$request_id" "$request_id"
            continue
        fi
        case "$request_operation" in
            capture)
                case "$state" in
                    file)
                        if ! metadata=$(stat -c '%a %u %g' -- "$path"); then
                            printf 'result %s error\\nend %s\\n' "$request_id" "$request_id"
                            continue
                        fi
                        if ! encoded=$(base64 < "$path"); then
                            printf 'result %s error\\nend %s\\n' "$request_id" "$request_id"
                            continue
                        fi
                        printf 'result %s file %s\\n' "$request_id" "$metadata"
                        printf '%s' "$encoded" | tr -d '\\n'
                        printf '\\nend %s\\n' "$request_id"
                        ;;
                    escape|symlink|other|missing)
                        printf 'result %s %s\\nend %s\\n' "$request_id" "$state" "$request_id"
                        ;;
                    *) exit 65 ;;
                esac
                ;;
            stat)
                printf 'result %s %s\\nend %s\\n' "$request_id" "$state" "$request_id"
                ;;
            *) exit 64 ;;
        esac
    done
}
# compose2role-source-session-ready
main
"""


class _RemoteSourceSession:
    """One framed SSH session for all source reads needed by a remote project."""

    def __init__(self, host: str, *, use_sudo: bool) -> None:
        remote_command: tuple[str, ...] = ("sh", "-s")
        if use_sudo:
            remote_command = ("sudo", "-n", *remote_command)
        try:
            process: Popen[bytes] = Popen(
                ssh_command(host, remote_command),
                stdin=PIPE,
                stdout=PIPE,
                stderr=DEVNULL,
            )
        except FileNotFoundError as error:
            raise RemoteProjectError(
                "ssh-client", "OpenSSH client executable 'ssh' was not found"
            ) from error
        if process.stdin is None or process.stdout is None:
            process.kill()
            raise RemoteProjectError("source", "remote source session could not be started")
        self._process = process
        self._stdin: IO[bytes] = process.stdin
        self._stdout: IO[bytes] = process.stdout
        self._line_buffer = b""
        self._next_request_id = 0
        self._closed = False
        try:
            self._write(_REMOTE_SOURCE_SESSION_SCRIPT)
            if self._read_line() != "ready":
                raise RemoteProjectError("source", "remote source session response is invalid")
        except RemoteProjectError:
            self.abort()
            raise

    def capture(self, root: PurePosixPath, path: PurePosixPath) -> SourceFile | str:
        """Capture PATH and its metadata, or return its source-boundary state."""
        return self._request("capture", root, path)

    def stat(self, root: PurePosixPath, path: PurePosixPath) -> str:
        """Return the source-boundary state of PATH without reading its bytes."""
        state = self._request("stat", root, path)
        if not isinstance(state, str):
            raise RemoteProjectError("source", "remote source session response is invalid")
        return state

    def close(self) -> None:
        """Finish the session and reject an abnormal remote exit or trailing output."""
        if self._closed:
            return
        try:
            self._stdin.close()
        except OSError:
            pass
        trailing = self._line_buffer + self._read_to_eof()
        try:
            returncode = self._process.wait(timeout=_SSH_TIMEOUT_SECONDS)
        except TimeoutExpired as error:
            self.abort()
            raise RemoteProjectError("timeout", "remote operation timed out") from error
        self._closed = True
        if returncode == 255:
            raise RemoteProjectError("ssh", "SSH connection or remote command failed")
        if returncode != 0:
            raise RemoteProjectError("source", "remote source validation failed")
        if trailing:
            raise RemoteProjectError("source", "remote source session response is invalid")

    def abort(self) -> None:
        """Close a failed session without replacing its original value-free error."""
        if self._closed:
            return
        self._closed = True
        try:
            self._stdin.close()
        except OSError:
            pass
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=_SSH_TIMEOUT_SECONDS)
            except TimeoutExpired:
                self._process.kill()
                self._process.wait()

    def _request(
        self, operation: str, root: PurePosixPath, path: PurePosixPath
    ) -> SourceFile | str:
        request_id = self._next_request_id
        self._next_request_id += 1
        self._write(f"request {request_id} {operation}\n{path}\n{root}\nend {request_id}\n")
        header = self._read_line().split()
        if len(header) < 3 or header[:2] != ["result", str(request_id)]:
            raise RemoteProjectError("source", "remote source session response is invalid")
        state = header[2]
        if state not in {"error", "escape", "file", "missing", "other", "symlink"}:
            raise RemoteProjectError("source", "remote source session response is invalid")
        if state == "error":
            self._expect_end(request_id)
            raise RemoteProjectError("source", "remote source request failed")
        if operation == "stat":
            if len(header) != 3:
                raise RemoteProjectError("source", "remote source session response is invalid")
            self._expect_end(request_id)
            return state
        if operation != "capture":
            raise RemoteProjectError("source", "remote source session response is invalid")
        if state != "file":
            if len(header) != 3:
                raise RemoteProjectError("source", "remote source session response is invalid")
            self._expect_end(request_id)
            return state
        if len(header) != 6:
            raise RemoteProjectError("source", "remote source session response is invalid")
        encoded_content = self._read_line()
        self._expect_end(request_id)
        metadata, content = _parse_captured_source_file(
            f"file {' '.join(header[3:])}\n{encoded_content}"
        )
        return SourceFile(
            relative_path=relative_source_path(root, path),
            content=content,
            metadata=metadata,
        )

    def _expect_end(self, request_id: int) -> None:
        if self._read_line() != f"end {request_id}":
            raise RemoteProjectError("source", "remote source session response is invalid")

    def _write(self, value: str) -> None:
        try:
            self._stdin.write(value.encode("utf-8"))
            self._stdin.flush()
        except (BrokenPipeError, OSError) as error:
            self._raise_closed(error)

    def _read_line(self) -> str:
        deadline = monotonic() + _SSH_TIMEOUT_SECONDS
        while True:
            separator = self._line_buffer.find(b"\n")
            if separator != -1:
                line = self._line_buffer[:separator]
                self._line_buffer = self._line_buffer[separator + 1 :]
                try:
                    return line.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise RemoteProjectError(
                        "source", "remote response was not valid UTF-8"
                    ) from error
            chunk = self._read_chunk(deadline)
            if not chunk:
                self._raise_closed()
            self._line_buffer += chunk

    def _read_to_eof(self) -> bytes:
        deadline = monotonic() + _SSH_TIMEOUT_SECONDS
        chunks = bytearray()
        while True:
            chunk = self._read_chunk(deadline)
            if not chunk:
                return bytes(chunks)
            chunks += chunk

    def _read_chunk(self, deadline: float) -> bytes:
        timeout = deadline - monotonic()
        if timeout <= 0:
            self.abort()
            raise RemoteProjectError("timeout", "remote operation timed out")
        readable, _, _ = select((self._stdout,), (), (), timeout)
        if not readable:
            self.abort()
            raise RemoteProjectError("timeout", "remote operation timed out")
        try:
            return os.read(self._stdout.fileno(), 8192)
        except OSError as error:
            self._raise_closed(error)

    def _raise_closed(self, error: OSError | None = None) -> NoReturn:
        try:
            returncode = self._process.wait(timeout=_SSH_TIMEOUT_SECONDS)
        except TimeoutExpired:
            self.abort()
            returncode = None
        if returncode == 255:
            message = ("ssh", "SSH connection or remote command failed")
        else:
            message = ("source", "remote source session closed unexpectedly")
        if error is None:
            raise RemoteProjectError(*message)
        raise RemoteProjectError(*message) from error


RemoteProjectError = ProjectResolutionError


class RemoteCapture(ProjectCapture):
    """Adapt the framed SSH source session to the shared capture seam."""

    def __init__(self, host: str, *, use_sudo: bool) -> None:
        self._session = _RemoteSourceSession(host, use_sudo=use_sudo)

    def capture(self, root: PurePosixPath, path: PurePosixPath) -> SourceFile | str:
        """Capture PATH and its metadata, or return its source-boundary state."""
        return self._session.capture(root, path)

    def stat(self, root: PurePosixPath, path: PurePosixPath) -> str:
        """Return the source-boundary state of PATH without reading its bytes."""
        return self._session.stat(root, path)

    def close(self) -> None:
        """Finish the session and reject an abnormal remote exit."""
        self._session.close()

    def abort(self) -> None:
        """Discard the session without replacing the original value-free error."""
        self._session.abort()


class RemoteComposeCanonicalizer(Canonicalizer):
    """Resolve a remote project through Docker Compose's canonical JSON model."""

    def __init__(
        self, host: str, *, use_sudo: bool, docker_context: str | None = None
    ) -> None:
        self._host = host
        self._use_sudo = use_sudo
        self._docker_context = docker_context

    def canonicalize(
        self,
        identity: DiscoveredProject,
        root: PurePosixPath,
        files: tuple[PurePosixPath, ...],
    ) -> CanonicalResult:
        """Return the effective Compose document for the captured project."""
        config_files = tuple(str(root.joinpath(*file.parts)) for file in files)
        payload = "\n".join(("config", identity.name, str(root), *config_files)) + "\n"
        output = _run_remote_config(
            self._host,
            identity.name,
            payload,
            use_sudo=self._use_sudo,
            docker_context=self._docker_context,
        )
        try:
            document: object = json.loads(output)
        except JSONDecodeError as error:
            raise RemoteProjectError(
                "invalid-json", "remote Docker Compose returned invalid canonical JSON"
            ) from error
        return CanonicalResult(document=_canonical_document(document))


def resolve_remote_projects(
    host: str,
    *,
    project_name: str | None,
    all_projects: bool,
    use_sudo: bool,
    secret_policy: SecretPolicy | None,
    docker_context: str | None = None,
    on_outcome: Callable[[AuditOutcome], None] | None = None,
) -> AuditResult:
    """Resolve a selected remote project or all discovered projects in isolation."""
    try:
        projects = discover_projects(
            host,
            use_sudo=use_sudo,
            include_working_directories=True,
            docker_context=docker_context,
        )
    except RemoteCommandError as error:
        raise RemoteProjectError(
            error.category,
            _DISCOVERY_MESSAGES.get(error.category, "remote Docker Compose discovery failed"),
        ) from error
    if project_name is not None:
        selected_projects = tuple(project for project in projects if project.name == project_name)
        if not selected_projects:
            failure = ProjectFailure(
                name=project_name,
                category="unknown-project",
                message="the requested remote Compose project was not discovered",
            )
            if on_outcome is not None:
                on_outcome(failure)
            return AuditResult(
                projects=(),
                failures=(failure,),
                outcomes=(failure,),
            )
    elif all_projects:
        selected_projects = projects
    else:
        raise ValueError("remote project selection is required")

    resolved: list[ResolvedProject] = []
    failures: list[ProjectFailure] = []
    outcomes: list[AuditOutcome] = []
    for project in selected_projects:
        try:
            resolution = _resolve_remote_project(
                host,
                project,
                use_sudo=use_sudo,
                secret_policy=secret_policy,
                docker_context=docker_context,
            )
            resolved.append(resolution)
            outcome: AuditOutcome = resolution
        except RemoteProjectError as error:
            failure = ProjectFailure(
                name=project.name,
                category=error.category,
                message=str(error),
            )
            failures.append(failure)
            outcome = failure
        outcomes.append(outcome)
        if on_outcome is not None:
            on_outcome(outcome)
    return AuditResult(
        projects=tuple(resolved),
        failures=tuple(failures),
        outcomes=tuple(outcomes),
    )


def _resolve_remote_project(
    host: str,
    project: DiscoveredProject,
    *,
    use_sudo: bool,
    secret_policy: SecretPolicy | None,
    docker_context: str | None,
) -> ResolvedProject:
    return resolve_project(
        RemoteCapture(host, use_sudo=use_sudo),
        RemoteComposeCanonicalizer(
            host, use_sudo=use_sudo, docker_context=docker_context
        ),
        project,
        secret_policy,
    )


def _canonical_document(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RemoteProjectError(
            "invalid-model", "remote Docker Compose returned an unsupported effective model"
        )
    document: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise RemoteProjectError(
                "invalid-model", "remote Docker Compose returned an unsupported effective model"
            )
        document[key] = item
    return document


def _parse_captured_source_file(output: str) -> tuple[FileMetadata, bytes]:
    """Decode one captured file header and its base64 content line."""
    header, separator, encoded_content = output.partition("\n")
    if not separator:
        raise RemoteProjectError("source", "remote source metadata is invalid")

    fields = header.split()
    if len(fields) != 4 or fields[0] != "file":
        raise RemoteProjectError("source", "remote source metadata is invalid")
    mode, uid, gid = fields[1:]
    if (
        not mode
        or len(mode) > 4
        or any(character not in "01234567" for character in mode)
        or len(uid) > 10
        or not uid.isascii()
        or not uid.isdecimal()
        or len(gid) > 10
        or not gid.isascii()
        or not gid.isdecimal()
    ):
        raise RemoteProjectError("source", "remote source metadata is invalid")
    try:
        content = base64.b64decode(encoded_content.strip(), validate=True)
    except (binascii.Error, ValueError) as error:
        raise RemoteProjectError("source", "remote source content is invalid") from error
    return FileMetadata(mode=int(mode, 8), uid=int(uid), gid=int(gid)), content


def _run_remote_config(
    host: str,
    project_name: str,
    payload: str,
    *,
    use_sudo: bool,
    docker_context: str | None,
) -> str:
    return _run_remote_operation(
        host,
        project_name,
        payload,
        use_sudo=use_sudo,
        docker_context=docker_context,
        category="remote-compose",
        failure_message=f"remote Compose resolution failed for project {project_name!r}",
    )


def _run_remote_operation(
    host: str,
    project_name: str,
    payload: str,
    *,
    use_sudo: bool,
    category: str,
    failure_message: str,
    docker_context: str | None = None,
) -> str:
    remote_command: tuple[str, ...] = ("sh", "-s")
    if use_sudo:
        remote_command = ("sudo", "-n", *remote_command)
    try:
        result = run(
            ssh_command(host, remote_command),
            check=False,
            capture_output=True,
            input=_operation_script(payload, docker_context),
            text=True,
            encoding="utf-8",
            timeout=_SSH_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise RemoteProjectError(
            "ssh-client", "OpenSSH client executable 'ssh' was not found"
        ) from error
    except TimeoutExpired as error:
        raise RemoteProjectError("timeout", "remote operation timed out") from error
    except UnicodeDecodeError as error:
        raise RemoteProjectError(category, "remote response was not valid UTF-8") from error

    if result.returncode == 255:
        raise RemoteProjectError("ssh", "SSH connection or remote command failed")
    if result.returncode != 0:
        raise RemoteProjectError(category, failure_message)
    return result.stdout


def _operation_script(payload: str, docker_context: str | None = None) -> str:
    encoded_payload = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    docker = (
        "docker"
        if docker_context is None
        else f"docker --context {shlex.quote(docker_context)}"
    )
    prefix = _REMOTE_OPERATION_PREFIX % {"docker": docker}
    return f"{prefix}{encoded_payload}\n{_REMOTE_OPERATION_SUFFIX}"
