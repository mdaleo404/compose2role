"""Discover Compose projects on a remote Docker host through OpenSSH."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from json import JSONDecodeError
from subprocess import TimeoutExpired, run

from compose2role.errors import DockerContextError, RemoteCommandError

_SSH_TIMEOUT_SECONDS = 30
_DOCKER_CONTEXT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_WORKING_DIRECTORY_FORMAT = (
    "'{{.Label \"com.docker.compose.project\"}}\t"
    "{{.Label \"com.docker.compose.project.working_dir\"}}'"
)


@dataclass(frozen=True)
class DiscoveredProject:
    """The remote Compose project details Docker exposes without a filesystem scan."""

    name: str
    status: str
    config_files: tuple[str, ...]
    working_directories: tuple[str, ...] = ()

    def as_json(self) -> dict[str, str | list[str]]:
        """Return the stable JSON form emitted by the CLI."""
        return {
            "name": self.name,
            "status": self.status,
            "config_files": list(self.config_files),
        }


def discover_projects(
    host: str,
    *,
    use_sudo: bool = False,
    include_working_directories: bool = False,
    docker_context: str | None = None,
) -> tuple[DiscoveredProject, ...]:
    """Ask Docker Compose on HOST for its known project config files."""
    remote_command = docker_command(
        ("compose", "ls", "--all", "--format", "json"), docker_context=docker_context
    )
    if use_sudo:
        remote_command = ("sudo", "-n", *remote_command)
    command = ssh_command(host, remote_command)
    try:
        result = run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=_SSH_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise RemoteCommandError(
            "OpenSSH client executable 'ssh' was not found", category="ssh-client"
        ) from error
    except TimeoutExpired as error:
        raise RemoteCommandError(
            f"SSH discovery timed out for host {host!r}", category="ssh-timeout"
        ) from error

    if result.returncode != 0:
        if result.returncode == 255:
            raise RemoteCommandError(
                _error_message(
                    f"SSH connection or remote command failed for host {host!r} (exit 255)",
                    result.stderr,
                ),
                category="ssh",
            )
        if use_sudo:
            raise RemoteCommandError(
                _error_message(
                    f"remote Docker discovery failed for host {host!r}; "
                    "ensure the SSH user has passwordless sudo access to Docker",
                    result.stderr,
                ),
                category="remote-discovery",
            )
        raise RemoteCommandError(
            _error_message(
                f"remote Docker discovery failed for host {host!r}; "
                "the SSH user may not be able to reach the daemon: "
                "join the docker group, configure passwordless sudo, "
                "or name a Docker context with --docker-context",
                result.stderr,
            ),
            category="remote-discovery",
        )
    projects = _parse_projects(result.stdout)
    if not include_working_directories:
        return projects
    working_directories = _discover_working_directories(
        host, use_sudo=use_sudo, docker_context=docker_context
    )
    return tuple(
        replace(project, working_directories=working_directories.get(project.name, ()))
        for project in projects
    )


def _discover_working_directories(
    host: str, *, use_sudo: bool, docker_context: str | None
) -> dict[str, tuple[str, ...]]:
    remote_command: tuple[str, ...] = docker_command(
        ("ps", "--all", "--format", _WORKING_DIRECTORY_FORMAT),
        docker_context=docker_context,
    )
    if use_sudo:
        remote_command = ("sudo", "-n", *remote_command)
    try:
        result = run(
            ssh_command(host, remote_command),
            check=False,
            capture_output=True,
            text=True,
            timeout=_SSH_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, TimeoutExpired):
        return {}
    if result.returncode != 0:
        return {}
    return _parse_working_directories(result.stdout)


def _parse_working_directories(output: str) -> dict[str, tuple[str, ...]]:
    try:
        json_payload: object = json.loads(output)
    except JSONDecodeError:
        json_payload = None
    if isinstance(json_payload, list):
        # A JSON listing cannot carry the tab-separated label format, so labels are unavailable.
        return {}
    directories: dict[str, set[str]] = {}
    for line in output.splitlines():
        if not line:
            continue
        if line.count("\t") != 1:
            raise RemoteCommandError(
                "remote Docker returned invalid Compose project working-directory labels",
                category="invalid-discovery",
            )
        project, directory = line.split("\t")
        if not project and not directory:
            continue
        if (
            not project
            or not directory
            or _has_control_characters(project)
            or _has_control_characters(directory)
        ):
            raise RemoteCommandError(
                "remote Docker returned invalid Compose project working-directory labels",
                category="invalid-discovery",
            )
        directories.setdefault(project, set()).add(directory)
    return {project: tuple(sorted(values)) for project, values in directories.items()}


def validate_docker_context(context: str) -> str:
    """Return CONTEXT when it is one safe argv word, otherwise reject it."""
    if not _DOCKER_CONTEXT_NAME.fullmatch(context):
        raise DockerContextError(
            f"invalid Docker context name: {context!r}; "
            "use a letter or digit followed by letters, digits, '_', '.', or '-'"
        )
    return context


def docker_command(
    command: tuple[str, ...], *, docker_context: str | None
) -> tuple[str, ...]:
    """Build a remote Docker argv, naming the context when one is selected."""
    if docker_context is None:
        return ("docker", *command)
    return ("docker", "--context", docker_context, *command)


def ssh_command(host: str, remote_command: tuple[str, ...]) -> list[str]:
    """Build an OpenSSH argv without changing SSH's configured connection behavior."""
    destination, port = _parse_destination(host)
    command = ["ssh"]
    if port is not None:
        command.extend(("-p", port))
    command.extend(("--", destination, *remote_command))
    return command


def _error_message(message: str, stderr: str) -> str:
    detail = stderr.strip()
    return f"{message}: {detail}" if detail else message


def _parse_projects(output: str) -> tuple[DiscoveredProject, ...]:
    try:
        payload: object = json.loads(output)
    except JSONDecodeError as error:
        raise RemoteCommandError(
            "remote Docker Compose returned invalid JSON", category="invalid-json"
        ) from error

    if not isinstance(payload, list):
        raise RemoteCommandError(
            "remote Docker Compose returned an invalid project list", category="invalid-discovery"
        )

    projects: list[DiscoveredProject] = []
    for item in payload:
        if not isinstance(item, dict):
            raise RemoteCommandError(
                "remote Docker Compose returned an invalid project entry",
                category="invalid-discovery",
            )
        name: object = item.get("Name")
        status: object = item.get("Status", "")
        config_files: object = item.get("ConfigFiles", "")
        if not isinstance(name, str) or not name or _has_control_characters(name):
            raise RemoteCommandError(
                "remote Docker Compose returned a project without a name",
                category="invalid-discovery",
            )
        if not isinstance(status, str) or _has_control_characters(status):
            raise RemoteCommandError(
                "remote Docker Compose returned an invalid project status",
                category="invalid-discovery",
            )
        projects.append(
            DiscoveredProject(
                name=name,
                status=status,
                config_files=_config_files(config_files),
            )
        )
    return tuple(projects)


def _config_files(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        paths = tuple(path for path in value.split(",") if path)
    elif isinstance(value, list) and all(isinstance(path, str) for path in value):
        paths = tuple(value)
    else:
        raise RemoteCommandError(
            "remote Docker Compose returned invalid config file paths", category="invalid-discovery"
        )
    if any(_has_control_characters(path) for path in paths):
        raise RemoteCommandError(
            "remote Docker Compose returned invalid config file paths", category="invalid-discovery"
        )
    return paths


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _parse_destination(host: str) -> tuple[str, str | None]:
    if not host:
        raise RemoteCommandError("SSH host must not be empty")
    if host.count(":") != 1:
        return host, None

    destination, possible_port = host.rsplit(":", maxsplit=1)
    if not possible_port.isascii() or not possible_port.isdecimal():
        return host, None
    port_number = int(possible_port)
    if not destination or not 1 <= port_number <= 65535:
        raise RemoteCommandError(f"SSH port is invalid for host {host!r}")
    return destination, possible_port
