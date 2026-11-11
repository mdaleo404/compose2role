"""Preflight checks for tools, repository configuration, and generated roles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path, PurePosixPath
from stat import S_IMODE
from subprocess import CompletedProcess, TimeoutExpired, run
from typing import Literal

from compose2role.discover import docker_command, ssh_command
from compose2role.errors import GenerationError, SecretPolicyError
from compose2role.layout import AnsibleLayout
from compose2role.remote_emit import (
    normalized_compose_hash,
    normalized_dotenv_hash,
    normalized_file_secret_hash,
)
from compose2role.secret_policy import load_secret_policy
from compose2role.sops import SOPS_TARGET, validate_sops_config
from compose2role.source import FileMetadata

DoctorStatus = Literal["ok", "warning", "error"]
DistroFamily = Literal["debian", "rhel"] | None
RoleDriftState = Literal["unchanged", "source changed", "source unavailable", "invalid"]

OS_RELEASE_PATH = Path("/etc/os-release")
_PROVENANCE_FILE = ".compose2role.json"
_BACKUP_DIRECTORY = Path(".compose2role") / "backups"
_REQUIRED_COLLECTIONS = ("community.docker", "community.sops")
_TIMEOUT_SECONDS = 30
# Single-quoted because OpenSSH joins the remote argv with spaces and the remote shell re-splits it.
_DOCKER_INFO_FORMAT = "'{{json .}}'"


@dataclass(frozen=True)
class DoctorCheck:
    """One value-free diagnostic result with an optional remediation hint."""

    name: str
    status: DoctorStatus
    detail: str
    hint: str | None = None
    required: bool = False

    def as_json(self) -> dict[str, object]:
        """Return the stable JSON form of one check."""
        payload: dict[str, object] = {
            "detail": self.detail,
            "name": self.name,
            "required": self.required,
            "status": self.status,
        }
        if self.hint is not None:
            payload["hint"] = self.hint
        return payload


@dataclass(frozen=True)
class DoctorReport:
    """Every check for one selected mode and its exit-relevant summary."""

    target: dict[str, str]
    checks: tuple[DoctorCheck, ...]

    @property
    def failed(self) -> bool:
        """Return whether a check required for the selected mode failed."""
        return any(check.status == "error" and check.required for check in self.checks)

    def as_json(self) -> dict[str, object]:
        """Return the value-free doctor envelope."""
        return {
            "checks": [check.as_json() for check in self.checks],
            "summary": self.summary(),
            "target": dict(self.target),
        }

    def summary(self) -> dict[str, object]:
        """Return the status counts shared by text and JSON output."""
        return {
            "errors": sum(1 for check in self.checks if check.status == "error"),
            "failed": self.failed,
            "ok": sum(1 for check in self.checks if check.status == "ok"),
            "warnings": sum(1 for check in self.checks if check.status == "warning"),
        }


def target_for(host: str | None) -> dict[str, str]:
    """Return the selected mode's value-free JSON target."""
    if host is None:
        return {"kind": "local"}
    return {"kind": "remote", "host": host}


@dataclass(frozen=True)
class _Distro:
    family: DistroFamily


def diagnose(
    layout: AnsibleLayout,
    *,
    host: str | None = None,
    use_sudo: bool = False,
    docker_context: str | None = None,
    environ: Mapping[str, str] | None = None,
    os_release_path: Path | None = None,
) -> DoctorReport:
    """Run every check required by the selected local or remote mode."""
    environment = os.environ if environ is None else environ
    distro = _read_distro(OS_RELEASE_PATH if os_release_path is None else os_release_path)
    checks: list[DoctorCheck] = []
    if host is None:
        checks.extend((_config_check(layout), _layout_check(layout)))
        checks.append(_secret_policy_check(layout))
        checks.append(_output_check(layout.roles_directory))
        checks.extend(
            (
                _sops_check(environment, distro),
                _gpg_check(environment, distro),
                _sops_rule_check(layout.sops_config),
            )
        )
        galaxy = _resolve_ansible_tool("ansible-galaxy", environment)
        checks.extend(
            (
                _ansible_tool_check("ansible-galaxy", galaxy, distro),
                _collections_check(galaxy, layout, environment, distro),
                _ansible_tool_check(
                    "ansible-lint",
                    _resolve_ansible_tool("ansible-lint", environment),
                    distro,
                ),
                _ansible_tool_check(
                    "ansible-playbook",
                    _resolve_ansible_tool("ansible-playbook", environment),
                    distro,
                ),
                _roles_check(layout.roles_directory),
                _drift_check(layout.roles_directory),
                _backups_check(layout.roles_directory),
            )
        )
    else:
        ssh = _resolve_executable("ssh", "COMPOSE2ROLE_SSH_BIN", environment)
        checks.extend(
            _remote_checks(ssh, host, use_sudo, docker_context, environment, distro)
        )
    target = target_for(host)
    return DoctorReport(target=target, checks=tuple(checks))


def _config_check(layout: AnsibleLayout) -> DoctorCheck:
    if layout.config.path is not None:
        detail = f"repository configuration: {layout.config.path}"
    else:
        detail = f"no repository configuration discovered; using {layout.root}"
    return DoctorCheck("config", "ok", detail)


def _layout_check(layout: AnsibleLayout) -> DoctorCheck:
    detail = f"roles {layout.roles_directory}; inventory {len(layout.inventory)} path(s)"
    return DoctorCheck("layout", "ok", detail)


def _secret_policy_check(layout: AnsibleLayout) -> DoctorCheck:
    if layout.secret_policy is None:
        return DoctorCheck("secret policy", "ok", "no secret policy configured")
    try:
        load_secret_policy(layout.secret_policy)
    except SecretPolicyError as error:
        return DoctorCheck(
            "secret policy",
            "warning",
            str(error),
            hint=f"fix the secret policy at {layout.secret_policy}",
        )
    return DoctorCheck("secret policy", "ok", f"secret policy loaded: {layout.secret_policy}")


def _output_check(roles_directory: Path) -> DoctorCheck:
    writable, checked = _writable_directory(roles_directory)
    if writable:
        return DoctorCheck("output", "ok", f"roles directory is writable: {checked}")
    return DoctorCheck(
        "output",
        "error",
        f"roles directory is not writable: {checked}",
        hint=f"make {checked} writable or pass --output",
        required=True,
    )


def _remote_checks(
    ssh: str | None,
    host: str,
    use_sudo: bool,
    docker_context: str | None,
    environment: Mapping[str, str],
    distro: _Distro,
) -> tuple[DoctorCheck, ...]:
    if ssh is None:
        return (
            DoctorCheck(
                "ssh",
                "error",
                "OpenSSH client executable 'ssh' was not found",
                hint=_package_hint(_openssh_package(distro), distro),
                required=True,
            ),
        )
    checks = [
        DoctorCheck("ssh", "ok", f"OpenSSH client executable: {ssh}"),
        _ssh_resolution_check(ssh, host, environment),
        _remote_docker_check(ssh, host, use_sudo, docker_context, environment),
        _remote_compose_check(ssh, host, use_sudo, docker_context, environment),
    ]
    return tuple(checks)


def _ssh_resolution_check(
    ssh: str, host: str, environment: Mapping[str, str]
) -> DoctorCheck:
    command = ssh_command(host, ())
    argv = [ssh, "-G", *command[1:]]
    result = _run(argv, environment)
    if result is None or result.returncode != 0:
        return DoctorCheck(
            "ssh resolution",
            "error",
            f"ssh -G {host} failed",
            hint="check the SSH host alias and OpenSSH configuration",
            required=True,
        )
    fields = _ssh_config_fields(result.stdout)
    detail = (
        f"ssh -G {host} resolved hostname {fields.get('hostname', 'unknown')}, "
        f"user {fields.get('user', 'unknown')}, port {fields.get('port', 'unknown')}"
    )
    return DoctorCheck("ssh resolution", "ok", detail)


def _remote_docker_check(
    ssh: str,
    host: str,
    use_sudo: bool,
    docker_context: str | None,
    environment: Mapping[str, str],
) -> DoctorCheck:
    info = _run_remote(
        ssh,
        host,
        docker_command(
            ("info", "--format", _DOCKER_INFO_FORMAT), docker_context=docker_context
        ),
        use_sudo=use_sudo,
        environment=environment,
    )
    if info is None or info.returncode != 0:
        return DoctorCheck(
            "remote docker",
            "error",
            f"remote Docker daemon is not reachable on {host}",
            hint=(
                "join the docker group, configure passwordless sudo, "
                "or name a context with --docker-context"
            ),
            required=True,
        )
    mode = _daemon_mode(info.stdout)
    projects = _remote_project_count(ssh, host, use_sudo, docker_context, environment)
    detail = (
        f"remote Docker daemon is {mode}"
        if mode is not None
        else "remote Docker daemon is reachable"
    )
    if projects is None:
        detail = f"{detail}; visible Compose projects unavailable"
    else:
        detail = f"{detail}; {projects} visible Compose project(s)"
    return DoctorCheck("remote docker", "ok", detail)


def _remote_project_count(
    ssh: str,
    host: str,
    use_sudo: bool,
    docker_context: str | None,
    environment: Mapping[str, str],
) -> int | None:
    result = _run_remote(
        ssh,
        host,
        docker_command(
            ("compose", "ls", "--all", "--format", "json"), docker_context=docker_context
        ),
        use_sudo=use_sudo,
        environment=environment,
    )
    if result is None or result.returncode != 0:
        return None
    try:
        payload: object = json.loads(result.stdout)
    except JSONDecodeError:
        return None
    return len(payload) if isinstance(payload, list) else None


def _run_remote(
    ssh: str,
    host: str,
    remote_command: tuple[str, ...],
    *,
    use_sudo: bool,
    environment: Mapping[str, str],
) -> CompletedProcess[str] | None:
    if use_sudo:
        remote_command = ("sudo", "-n", *remote_command)
    command = ssh_command(host, remote_command)
    return _run([ssh, *command[1:]], environment)


def _remote_compose_check(
    ssh: str,
    host: str,
    use_sudo: bool,
    docker_context: str | None,
    environment: Mapping[str, str],
) -> DoctorCheck:
    result = _run_remote(
        ssh,
        host,
        docker_command(("compose", "version"), docker_context=docker_context),
        use_sudo=use_sudo,
        environment=environment,
    )
    if result is None or result.returncode != 0:
        return DoctorCheck(
            "remote compose",
            "error",
            f"remote docker compose version failed on {host}",
            hint="verify SSH access and install the Docker Compose v2 or newer plugin",
            required=True,
        )
    version = _compose_version(result.stdout)
    major = _compose_major(version)
    if major is None:
        return DoctorCheck(
            "remote compose",
            "error",
            f"remote Docker Compose version is unreadable: {version}",
            hint="install the Docker Compose v2 or newer plugin on the host",
            required=True,
        )
    if major < 2:
        return DoctorCheck(
            "remote compose",
            "error",
            f"remote Docker Compose is {version}; compose2role requires v2 or newer",
            hint="install the Docker Compose v2 or newer plugin on the host",
            required=True,
        )
    return DoctorCheck("remote compose", "ok", f"remote docker compose {version}")


def _sops_check(environment: Mapping[str, str], distro: _Distro) -> DoctorCheck:
    executable = _resolve_executable("sops", "COMPOSE2ROLE_SOPS_BIN", environment)
    if executable is None:
        return DoctorCheck(
            "sops",
            "warning",
            "sops executable was not found",
            hint=_package_hint("sops", distro),
        )
    result = _run([executable, "--version"], environment)
    if result is None or result.returncode != 0:
        return DoctorCheck(
            "sops",
            "warning",
            "sops --version failed",
            hint="verify the sops installation",
        )
    return DoctorCheck("sops", "ok", _first_line(result.stdout) or f"sops: {executable}")


def _gpg_check(environment: Mapping[str, str], distro: _Distro) -> DoctorCheck:
    executable = _resolve_executable("gpg", None, environment)
    if executable is None:
        package = "gnupg2" if distro.family == "rhel" else "gnupg"
        return DoctorCheck(
            "gpg",
            "warning",
            "gpg executable was not found",
            hint=_package_hint(package, distro),
        )
    return DoctorCheck("gpg", "ok", f"gpg executable: {executable}")


def _sops_rule_check(path: Path | None) -> DoctorCheck:
    if path is None:
        return DoctorCheck("sops rule", "ok", "no SOPS configuration configured")
    try:
        validate_sops_config(path)
    except GenerationError as error:
        return DoctorCheck(
            "sops rule",
            "error",
            str(error),
            hint=f"define a creation rule for {SOPS_TARGET} in {path}",
            required=True,
        )
    return DoctorCheck("sops rule", "ok", f"creation rule covers {SOPS_TARGET}: {path}")


def _ansible_tool_check(name: str, executable: str | None, distro: _Distro) -> DoctorCheck:
    if executable is None:
        package = "ansible-lint" if name == "ansible-lint" else _ansible_package(distro)
        return DoctorCheck(
            name,
            "warning",
            f"{name} executable was not found",
            hint=_package_hint(package, distro),
        )
    return DoctorCheck(name, "ok", f"{name} executable: {executable}")


def _collections_check(
    galaxy: str | None,
    layout: AnsibleLayout,
    environment: Mapping[str, str],
    distro: _Distro,
) -> DoctorCheck:
    if galaxy is None:
        return DoctorCheck(
            "ansible collections",
            "warning",
            "installed collections were not checked because ansible-galaxy was not found",
            hint=_package_hint(_ansible_package(distro), distro),
        )
    result = _run([galaxy, "collection", "list", "--format", "json"], environment)
    if result is None or result.returncode != 0:
        return DoctorCheck(
            "ansible collections",
            "warning",
            "ansible-galaxy collection list failed",
            hint="verify the ansible-galaxy installation",
        )
    installed = _installed_collections(result.stdout)
    if installed is None:
        return DoctorCheck(
            "ansible collections",
            "warning",
            "ansible-galaxy returned invalid collection data",
        )
    for name, version in _local_collections(layout, environment).items():
        installed.setdefault(name, version)
    missing = [name for name in _REQUIRED_COLLECTIONS if name not in installed]
    if missing:
        return DoctorCheck(
            "ansible collections",
            "warning",
            f"missing collections: {', '.join(missing)}",
            hint=f"install with: ansible-galaxy collection install {' '.join(missing)}",
        )
    found = ", ".join(
        f"{name} {installed[name]}".rstrip() for name in _REQUIRED_COLLECTIONS
    )
    return DoctorCheck("ansible collections", "ok", f"found {found}")


def _roles_check(roles_directory: Path) -> DoctorCheck:
    roles = _managed_roles(roles_directory)
    if not roles:
        return DoctorCheck("roles", "ok", "no generated roles yet")
    return DoctorCheck("roles", "ok", f"{len(roles)} generated role(s)")


def _drift_check(roles_directory: Path) -> DoctorCheck:
    managed = _managed_roles(roles_directory)
    if not managed:
        return DoctorCheck("drift", "ok", "no managed roles to compare")
    counts: dict[RoleDriftState, int] = {
        "unchanged": 0,
        "source changed": 0,
        "source unavailable": 0,
        "invalid": 0,
    }
    for role_directory in managed:
        counts[_role_drift(role_directory)] += 1
    detail = (
        f"{counts['unchanged']} unchanged, {counts['source changed']} source changed, "
        f"{counts['source unavailable']} source unavailable"
    )
    if counts["invalid"]:
        detail = f"{detail}, {counts['invalid']} unreadable provenance"
    if counts["source changed"] or counts["invalid"]:
        return DoctorCheck(
            "drift",
            "warning",
            detail,
            hint="run compose2role audit for an authoritative drift report",
        )
    return DoctorCheck("drift", "ok", detail)


def _backups_check(roles_directory: Path) -> DoctorCheck:
    directory = roles_directory / _BACKUP_DIRECTORY
    if not directory.is_dir():
        return DoctorCheck("backups", "ok", "no backups")
    try:
        count = sum(1 for entry in directory.iterdir() if entry.is_dir())
    except OSError:
        count = 0
    total = _directory_size(directory)
    hint = f"prune with: rm -r {directory}" if count else None
    return DoctorCheck(
        "backups",
        "ok",
        f"{count} backup(s), {_format_size(total)}",
        hint=hint,
    )


def _managed_roles(roles_directory: Path) -> tuple[Path, ...]:
    try:
        entries = sorted(roles_directory.iterdir())
    except OSError:
        return ()
    return tuple(
        entry
        for entry in entries
        if entry.is_dir()
        and not entry.is_symlink()
        and not entry.name.startswith(".")
        and (entry / _PROVENANCE_FILE).is_file()
    )


def _role_drift(role_directory: Path) -> RoleDriftState:
    """Compare recorded provenance hashes without re-resolving the project.

    ``audit`` remains the authoritative check because it re-captures the source.
    Doctor only needs a cheap, offline signal for each existing role.
    """
    try:
        document: object = json.loads(
            (role_directory / _PROVENANCE_FILE).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, JSONDecodeError):
        return "invalid"
    if not isinstance(document, dict):
        return "invalid"
    source = document.get("source")
    files = document.get("files")
    if not isinstance(source, dict) or not isinstance(files, dict):
        return "invalid"
    root_value = source.get("root")
    if not isinstance(root_value, str) or not root_value:
        return "invalid"
    root = Path(root_value)
    if not root.is_dir():
        return "source unavailable"
    for path, entry in files.items():
        if not isinstance(path, str) or not isinstance(entry, dict):
            return "invalid"
        if not _recorded_file_matches(root, path, entry):
            return "source changed"
    return "unchanged"


def _recorded_file_matches(
    root: Path, relative_path: str, entry: Mapping[str, object]
) -> bool:
    expected = entry.get("sha256")
    if not isinstance(expected, str):
        return False
    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        return False
    local_path = root.joinpath(*relative.parts)
    try:
        local_path.resolve().relative_to(root.resolve())
        metadata = local_path.stat()
        content = local_path.read_bytes()
    except (OSError, ValueError):
        return False
    if hashlib.sha256(content).hexdigest() == expected:
        return True
    file_metadata = FileMetadata(
        mode=S_IMODE(metadata.st_mode), uid=metadata.st_uid, gid=metadata.st_gid
    )
    return expected in {
        normalized_compose_hash(content),
        normalized_dotenv_hash(content),
        normalized_file_secret_hash(file_metadata),
    }


def _writable_directory(path: Path) -> tuple[bool, Path]:
    candidate = path
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    if not candidate.is_dir():
        return False, candidate
    return os.access(candidate, os.W_OK | os.X_OK), candidate


def _resolve_executable(
    name: str, override_name: str | None, environment: Mapping[str, str]
) -> str | None:
    search_path = environment.get("PATH", os.defpath)
    if override_name is not None:
        override = environment.get(override_name)
        if override:
            return shutil.which(override, path=search_path)
    return shutil.which(name, path=search_path)


def _resolve_ansible_tool(name: str, environment: Mapping[str, str]) -> str | None:
    override = environment.get("COMPOSE2ROLE_ANSIBLE_BIN")
    if override:
        candidate = Path(override).expanduser() / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None
    return shutil.which(name, path=environment.get("PATH", os.defpath))


def _installed_collections(output: str) -> dict[str, str] | None:
    try:
        payload: object = json.loads(output)
    except JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    found: dict[str, str] = {}
    for path_value in payload.values():
        if not isinstance(path_value, dict):
            continue
        for name, version_value in path_value.items():
            if not isinstance(name, str):
                continue
            version = ""
            if isinstance(version_value, dict):
                raw_version = version_value.get("version")
                if isinstance(raw_version, str):
                    version = raw_version
            found[name] = version
    return found


def _run(argv: list[str], environment: Mapping[str, str]) -> CompletedProcess[str] | None:
    try:
        return run(
            argv,
            check=False,
            capture_output=True,
            env=dict(environment),
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, OSError, TimeoutExpired):
        return None


def _read_distro(path: Path) -> _Distro:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return _Distro(None)
    values: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    tokens = {values.get("ID", "").lower(), *values.get("ID_LIKE", "").lower().split()}
    if tokens & {"debian", "ubuntu"}:
        return _Distro("debian")
    if tokens & {"rhel", "fedora", "centos", "rocky", "almalinux", "ol"}:
        return _Distro("rhel")
    return _Distro(None)


def _package_hint(package: str, distro: _Distro) -> str:
    if distro.family == "debian":
        return f"install with: sudo apt-get install {package}"
    if distro.family == "rhel":
        suffix = " (EPEL)" if package == "sops" else ""
        return f"install with: sudo dnf install {package}{suffix}"
    return f"install {package} with your package manager"


def _ansible_package(distro: _Distro) -> str:
    return "ansible-core" if distro.family == "rhel" else "ansible"


def _openssh_package(distro: _Distro) -> str:
    return "openssh-clients" if distro.family == "rhel" else "openssh-client"


def _directory_size(path: Path) -> int:
    total = 0
    for root, _directories, files in os.walk(path, followlinks=False):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
    return total


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    value = size / 1024
    for unit in ("KiB", "MiB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def _compose_version(text: str) -> str:
    version = _first_line(text) or "version unknown"
    prefix = "Docker Compose version "
    if version.startswith(prefix):
        version = version[len(prefix) :]
    return version


def _compose_major(version: str) -> int | None:
    match = re.match(r"v?(\d+)", version)
    return int(match.group(1)) if match is not None else None


def _ssh_config_fields(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(" ")
        if separator and key and value:
            fields.setdefault(key, value.strip())
    return fields


def _daemon_mode(output: str) -> str | None:
    """Return rootless or rootful from `docker info`; None when the payload is unusable."""
    try:
        payload: object = json.loads(output)
    except JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    options = payload.get("SecurityOptions")
    if not isinstance(options, list):
        return None
    return "rootless" if "name=rootless" in options else "rootful"


def _local_collections(
    layout: AnsibleLayout, environment: Mapping[str, str]
) -> dict[str, str]:
    """Find collections installed beside the repository or on ANSIBLE_COLLECTIONS_PATH."""
    roots: list[Path] = [
        Path(entry).expanduser()
        for entry in environment.get("ANSIBLE_COLLECTIONS_PATH", "").split(os.pathsep)
        if entry
    ]
    roots.append(layout.root / "collections")
    found: dict[str, str] = {}
    for root in roots:
        for base in (root / "ansible_collections", root):
            try:
                namespaces = sorted(base.iterdir())
            except OSError:
                continue
            for namespace in namespaces:
                if not namespace.is_dir():
                    continue
                try:
                    collections = sorted(namespace.iterdir())
                except OSError:
                    continue
                for collection in collections:
                    if collection.is_dir():
                        found.setdefault(f"{namespace.name}.{collection.name}", "")
    return found


def _first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:120]
    return ""
