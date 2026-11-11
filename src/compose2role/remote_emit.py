"""Render and atomically write source-faithful Compose roles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path, PurePosixPath
from typing import Literal

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from compose2role.errors import GenerationError
from compose2role.naming import normalize_role_name
from compose2role.resolve import FileDiff, PlanDiff, ResolvedProject
from compose2role.source import FileMetadata
from compose2role.source_fidelity import (
    SourceRoleMaterialization,
    SourceTemplate,
    materialize_source_role,
)

_ROLE_NAME = re.compile(r"[a-z][a-z0-9_]*")
_WriteState = Literal["generated", "unchanged"]
_PROVENANCE_FILE = PurePosixPath(".compose2role.json")


@dataclass(frozen=True)
class GeneratedFile:
    """One text or binary file in a generated role."""

    relative_path: PurePosixPath
    content: str | bytes
    classified_secret: bool = False


@dataclass(frozen=True)
class RolePlan:
    """A fully rendered role that has not been written yet."""

    role_name: str
    files: tuple[GeneratedFile, ...]
    secret_values: dict[str, str]


@dataclass(frozen=True)
class PlanComparison:
    """The value-free difference between a rendered plan and an existing role."""

    role_exists: bool
    unmanaged: bool
    added: tuple[str, ...]
    changed: tuple[str, ...]

    @property
    def identical(self) -> bool:
        """Return whether the existing role matches every planned file byte for byte."""
        return self.role_exists and not self.added and not self.changed


@dataclass(frozen=True)
class RoleWriteResult:
    """The outcome of placing one rendered role."""

    role_directory: Path
    state: _WriteState
    backup_directory: Path | None = None


def normalize_remote_role_name(project_name: str) -> str:
    """Derive a deterministic valid Ansible role name from a raw Compose project name."""
    role_name = normalize_role_name(project_name)
    if not _ROLE_NAME.fullmatch(role_name):
        raise GenerationError("remote project name cannot be normalized into an Ansible role name")
    return role_name


def preview_remote_role(
    project: ResolvedProject, role_name: str, *, docker_context: str | None = None
) -> RolePlan:
    """Render a source-faithful remote role without writing it."""
    _validate_role_name(role_name)
    materialization = materialize_source_role(project, role_name)
    return _preview_role(project, role_name, materialization, docker_context)


def _preview_role(
    project: ResolvedProject,
    role_name: str,
    materialization: SourceRoleMaterialization,
    docker_context: str | None,
) -> RolePlan:
    has_secrets = bool(materialization.secret_values)
    prerequisites = external_prerequisites(project.canonical_document)
    files: list[GeneratedFile] = [
        GeneratedFile(
            PurePosixPath("defaults/main.yml"),
            _render_source_defaults(
                role_name,
                materialization,
                str(project.source.root),
                project.project.name,
                docker_context,
            ),
        ),
        GeneratedFile(
            PurePosixPath("tasks/main.yml"),
            _render_source_tasks(
                role_name,
                materialization,
                tuple(source.relative_path for source in project.source.files),
                has_secrets,
                docker_context,
            ),
        ),
        GeneratedFile(PurePosixPath("meta/main.yml"), _render_meta(has_secrets)),
        GeneratedFile(
            PurePosixPath("meta/requirements.yml"), _render_requirements(has_secrets)
        ),
        GeneratedFile(
            PurePosixPath(".compose2role.json"),
            _render_provenance(project, role_name, prerequisites, materialization),
        ),
    ]
    files.extend(
        GeneratedFile(
            PurePosixPath("templates").joinpath(*template.relative_template_path.parts),
            template.content,
            classified_secret=template.has_secrets,
        )
        for template in materialization.templates
    )
    return RolePlan(
        role_name=role_name,
        files=tuple(files),
        secret_values=materialization.secret_values,
    )


def with_encrypted_secrets(plan: RolePlan, encrypted_secrets: bytes) -> RolePlan:
    """Attach real encrypted SOPS output to a rendered remote role plan."""
    if not plan.secret_values:
        raise GenerationError("remote role has no secrets to encrypt")
    return RolePlan(
        role_name=plan.role_name,
        files=(
            *plan.files,
            GeneratedFile(
                PurePosixPath("vars/secrets.sops.yml"),
                encrypted_secrets,
                classified_secret=True,
            ),
        ),
        secret_values=plan.secret_values,
    )


def compare_plan(plan: RolePlan, role_directory: Path) -> PlanComparison:
    """Compare a rendered plan with an existing role without writing anything."""
    if role_directory.is_symlink() or (
        role_directory.exists() and not role_directory.is_dir()
    ):
        raise GenerationError(f"existing role path must be a directory: {role_directory}")
    planned = _planned_files(plan)
    if not role_directory.exists():
        return PlanComparison(
            role_exists=False,
            unmanaged=False,
            added=tuple(sorted(str(path) for path in planned)),
            changed=(),
        )
    existing = _existing_role_files(role_directory)
    return PlanComparison(
        role_exists=True,
        unmanaged=_PROVENANCE_FILE not in existing,
        added=tuple(sorted(str(path) for path in planned if path not in existing)),
        changed=tuple(
            sorted(
                str(path)
                for path, content in planned.items()
                if path in existing and existing[path] != content
            )
        ),
    )


def diff_plan(plan: RolePlan, role_directory: Path) -> PlanDiff:
    """Compare a rendered plan with an existing role for value-free review."""
    if role_directory.is_symlink() or (
        role_directory.exists() and not role_directory.is_dir()
    ):
        raise GenerationError(f"existing role path must be a directory: {role_directory}")
    planned = {
        generated_file.relative_path: generated_file for generated_file in plan.files
    }
    if not role_directory.exists():
        existing: dict[PurePosixPath, bytes | None] = {}
        role_exists = False
        unmanaged = False
    else:
        existing = _existing_role_files(role_directory)
        role_exists = True
        unmanaged = _PROVENANCE_FILE not in existing

    files: list[FileDiff] = []
    for path in sorted(planned, key=str):
        generated_file = planned[path]
        content = _generated_file_bytes(generated_file)
        if path not in existing:
            change: Literal["added", "changed", "unchanged"] = "added"
            previous = b""
        elif existing[path] == content:
            change = "unchanged"
            previous = b""
        else:
            change = "changed"
            previous = existing[path] or b""
        withheld, withheld_reason = _withheld(generated_file)
        if unmanaged:
            withheld, withheld_reason = True, None
        if withheld:
            files.append(
                FileDiff(
                    path=str(path),
                    change=change,
                    withheld=True,
                    withheld_reason=withheld_reason,
                )
            )
        elif change == "unchanged":
            files.append(FileDiff(path=str(path), change=change))
        else:
            files.append(
                FileDiff(
                    path=str(path),
                    change=change,
                    old_text=_decode_diff_text(previous),
                    new_text=_decode_diff_text(content),
                )
            )
    return PlanDiff(role_exists=role_exists, unmanaged=unmanaged, files=tuple(files))


_DIFF_SAFE_PATHS = frozenset(
    {
        "defaults/main.yml",
        "tasks/main.yml",
        ".compose2role.json",
        "README.md",
        "site.yml",
        "site.yaml",
    }
)


def _is_safe_diff_path(path: PurePosixPath) -> bool:
    if str(path) in _DIFF_SAFE_PATHS:
        return True
    return bool(path.parts) and path.parts[0] == "meta"


def _withheld(generated_file: GeneratedFile) -> tuple[bool, str | None]:
    if generated_file.classified_secret:
        return True, "classified secret"
    if not _is_safe_diff_path(generated_file.relative_path):
        return True, None
    return False, None


def _decode_diff_text(content: bytes) -> str:
    return content.decode("utf-8", errors="replace")


def write_role(
    plan: RolePlan, output_directory: Path, *, force: bool = False
) -> RoleWriteResult:
    """Place a rendered role, refusing an existing differing role unless forced."""
    if output_directory.is_symlink() or (
        output_directory.exists() and not output_directory.is_dir()
    ):
        raise GenerationError("role output must be a directory")
    role_directory = output_directory / plan.role_name
    if role_directory.is_symlink() or (
        role_directory.exists() and not role_directory.is_dir()
    ):
        raise GenerationError(f"refusing to overwrite non-directory role path: {role_directory}")

    if not role_directory.exists():
        try:
            output_directory.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise GenerationError("role output could not be written") from error
        _install_new_role(plan, output_directory, role_directory)
        return RoleWriteResult(role_directory, "generated")

    comparison = compare_plan(plan, role_directory)
    if comparison.identical:
        return RoleWriteResult(role_directory, "unchanged")
    if not force:
        raise GenerationError(_refusal_message(comparison, role_directory))
    backup_directory = _replace_role(plan, output_directory, role_directory)
    return RoleWriteResult(role_directory, "generated", backup_directory=backup_directory)


def _refusal_message(comparison: PlanComparison, role_directory: Path) -> str:
    if comparison.unmanaged:
        return (
            f"refusing to overwrite unmanaged role {role_directory} "
            "(no .compose2role.json); use --force to replace it"
        )
    return (
        f"refusing to overwrite role {role_directory}: {_describe_changes(comparison)}; "
        "use --diff to review or --force to replace it"
    )


def _describe_changes(comparison: PlanComparison) -> str:
    changes: list[str] = []
    if comparison.added:
        changes.append(f"added: {', '.join(comparison.added)}")
    if comparison.changed:
        changes.append(f"changed: {', '.join(comparison.changed)}")
    return "; ".join(changes) if changes else "no file differences"


def _planned_files(plan: RolePlan) -> dict[PurePosixPath, bytes]:
    return {
        generated_file.relative_path: _generated_file_bytes(generated_file)
        for generated_file in plan.files
    }


def _generated_file_bytes(generated_file: GeneratedFile) -> bytes:
    if isinstance(generated_file.content, bytes):
        return generated_file.content
    return generated_file.content.encode("utf-8")


def _existing_role_files(role_directory: Path) -> dict[PurePosixPath, bytes | None]:
    files: dict[PurePosixPath, bytes | None] = {}
    for directory, _, names in os.walk(role_directory, followlinks=False):
        for name in names:
            path = Path(directory, name)
            relative_path = PurePosixPath(path.relative_to(role_directory).as_posix())
            files[relative_path] = _read_existing_file(path)
    return files


def _read_existing_file(path: Path) -> bytes | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return path.read_bytes()
    except OSError:
        return None


def _install_new_role(
    plan: RolePlan, output_directory: Path, role_directory: Path
) -> None:
    staging_directory = _stage_plan(plan, output_directory)
    try:
        if role_directory.exists() or role_directory.is_symlink():
            raise GenerationError(f"refusing to overwrite existing role: {role_directory}")
        os.replace(staging_directory, role_directory)
    except OSError as error:
        raise GenerationError("role output could not be written") from error
    finally:
        _discard_staging(staging_directory)


def _replace_role(
    plan: RolePlan, output_directory: Path, role_directory: Path
) -> Path:
    staging_directory = _stage_plan(plan, output_directory)
    backups_directory = output_directory / ".compose2role" / "backups"
    try:
        backups_directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        _discard_staging(staging_directory)
        raise GenerationError("role output could not be written") from error
    backup_directory = backups_directory / f"{plan.role_name}-{_utc_timestamp()}"
    try:
        os.replace(role_directory, backup_directory)
    except OSError as error:
        _discard_staging(staging_directory)
        raise GenerationError("role output could not be written") from error
    try:
        os.replace(staging_directory, role_directory)
    except OSError as error:
        try:
            os.replace(backup_directory, role_directory)
        except OSError as restore_error:
            raise GenerationError(
                "role output could not be written and the previous role could not be "
                f"restored; backup retained at {backup_directory}"
            ) from restore_error
        raise GenerationError(
            "role output could not be written; previous role restored"
        ) from error
    finally:
        _discard_staging(staging_directory)
    return backup_directory


def _stage_plan(plan: RolePlan, output_directory: Path) -> Path:
    try:
        staging_directory = Path(
            tempfile.mkdtemp(prefix=f".{plan.role_name}.", dir=output_directory)
        )
    except OSError as error:
        raise GenerationError("role output could not be written") from error
    try:
        for generated_file in plan.files:
            destination = staging_directory.joinpath(*generated_file.relative_path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(generated_file.content, bytes):
                destination.write_bytes(generated_file.content)
            else:
                destination.write_text(generated_file.content, encoding="utf-8")
    except OSError as error:
        _discard_staging(staging_directory)
        raise GenerationError("role output could not be written") from error
    return staging_directory


def _discard_staging(staging_directory: Path) -> None:
    if staging_directory.exists():
        shutil.rmtree(staging_directory, ignore_errors=True)


def _utc_timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def _validate_role_name(role_name: str) -> None:
    if not _ROLE_NAME.fullmatch(role_name):
        raise GenerationError("remote role name is invalid")


def _render_source_defaults(
    role_name: str,
    materialization: SourceRoleMaterialization,
    project_dir: str,
    compose_project_name: str,
    docker_context: str | None,
) -> str:
    lines = [
        "---",
        f"{role_name}_project_dir: {json.dumps(project_dir)}",
        f"{role_name}_compose_project_name: {json.dumps(compose_project_name)}",
    ]
    if docker_context is not None:
        lines.append(f"{role_name}_docker_context: {json.dumps(docker_context)}")
    for variable in materialization.variables:
        if not variable.is_secret:
            lines.append(f"{variable.name}: {json.dumps(variable.value)}")
    secret_names = [variable.name for variable in materialization.variables if variable.is_secret]
    if secret_names:
        lines.append(f"{role_name}_required_secrets:")
        lines.extend(f"  - {name}" for name in secret_names)
        lines.append(f'{role_name}_secrets_file: "{{{{ role_path }}}}/vars/secrets.sops.yml"')
    return "\n".join(lines) + "\n"


def _render_source_tasks(
    role_name: str,
    materialization: SourceRoleMaterialization,
    compose_files: tuple[PurePosixPath, ...],
    has_secrets: bool,
    docker_context: str | None,
) -> str:
    source_files = (
        *(template.source for template in materialization.templates),
        *(file_secret.source for file_secret in materialization.file_secrets),
    )
    directories = sorted(
        {
            source.relative_path.parent
            for source in source_files
            if source.relative_path.parent != PurePosixPath(".")
        },
        key=str,
    )
    directory_tasks = ""
    if directories:
        rendered_directories = "\n".join(
            f'    - "{{{{ {role_name}_project_dir }}}}/{directory}"' for directory in directories
        )
        directory_tasks = f"""\
- name: Create {role_name} source directories
  tags:
    - source
  ansible.builtin.file:
    path: "{{{{ item }}}}"
    state: directory
    mode: "0755"
  loop:
{rendered_directories}

"""
    rendered_sources = "\n\n".join(
        _render_source_file_task(role_name, template) for template in materialization.templates
    )
    rendered_compose_files = "\n".join(
        f"      - {json.dumps(str(compose_file))}" for compose_file in compose_files
    )
    secret_tasks = _render_source_secret_tasks(role_name) if has_secrets else ""
    file_secret_tasks = _render_file_secret_tasks(role_name, materialization)
    context_line = (
        f'    cli_context: "{{{{ {role_name}_docker_context }}}}"\n'
        if docker_context is not None
        else ""
    )
    return f"""\
---
- name: Ensure {role_name} Compose project directory exists
  tags:
    - source
  ansible.builtin.file:
    path: "{{{{ {role_name}_project_dir }}}}"
    state: directory
    mode: "0755"

{secret_tasks}{directory_tasks}{rendered_sources}

{file_secret_tasks}- name: Deploy {role_name} Compose project
  tags:
    - compose
  community.docker.docker_compose_v2:
    project_src: "{{{{ {role_name}_project_dir }}}}"
    project_name: "{{{{ {role_name}_compose_project_name }}}}"
{context_line}    files:
{rendered_compose_files}
    state: present
    pull: missing
    recreate: auto
    remove_orphans: false
"""


def _render_source_file_task(role_name: str, template: SourceTemplate) -> str:
    """Render one captured source file through a literal template task."""
    relative_path = template.source.relative_path
    metadata = template.source.metadata
    destination = f"{{{{ {role_name}_project_dir }}}}/{relative_path}"
    return f"""\
- name: {json.dumps(f"Render {relative_path}")}
  tags:
    - source
  ansible.builtin.template:
    src: {json.dumps(str(template.relative_template_path))}
    dest: {json.dumps(destination)}
    owner: "{metadata.uid}"
    group: "{metadata.gid}"
    mode: "{metadata.mode:04o}"
    newline_sequence: {json.dumps(template.newline_sequence)}
"""


def _render_source_secret_tasks(role_name: str) -> str:
    return f"""\
- name: Load {role_name} SOPS secrets
  tags:
    - secrets
  community.sops.load_vars:
    file: "{{{{ {role_name}_secrets_file }}}}"
    name: {role_name}_secrets
  no_log: true

- name: Assert {role_name} required secrets are present
  tags:
    - secrets
  ansible.builtin.assert:
    that: item in {role_name}_secrets
    fail_msg: "Missing secret: {{{{ item }}}}"
  loop: "{{{{ {role_name}_required_secrets }}}}"
  loop_control:
    label: "{{{{ item }}}}"

"""


def _render_file_secret_tasks(
    role_name: str, materialization: SourceRoleMaterialization
) -> str:
    if not materialization.file_secrets:
        return ""
    rendered_secrets = "\n".join(
        (
            f'    - path: {json.dumps(str(file_secret.source.relative_path))}\n'
            f'      key: {json.dumps(file_secret.variable_name)}\n'
            f'      owner: {json.dumps(str(file_secret.source.metadata.uid))}\n'
            f'      group: {json.dumps(str(file_secret.source.metadata.gid))}\n'
            f'      mode: "{file_secret.source.metadata.mode:04o}"'
        )
        for file_secret in materialization.file_secrets
    )
    return f"""\
- name: Render {role_name} file-backed Compose secrets
  tags:
    - secrets
  ansible.builtin.shell:
    cmd: |
      set -eu
      target="{{{{ ({role_name}_project_dir ~ '/' ~ item.path) | quote }}}}"
      owner="{{{{ item.owner }}}}"
      group="{{{{ item.group }}}}"
      mode="{{{{ item.mode }}}}"
      if [ -L "$target" ] || [ -d "$target" ]; then
        printf '%s\\n' 'unsafe file-secret target' >&2
        exit 4
      fi
      temporary=$(mktemp "$target.compose2role.XXXXXX")
      trap 'rm -f "$temporary"' EXIT
      base64 --decode > "$temporary"
      target_state="$(stat -c '%a:%u:%g' "$target" 2>/dev/null || true)"
      expected_mode="$(printf '%o' "$((0$mode))")"
      expected_state="$expected_mode:$owner:$group"
      if [ -f "$target" ] && cmp -s "$temporary" "$target"; then
        if [ "$target_state" = "$expected_state" ]; then
          exit 0
        fi
      fi
      install -o "$owner" -g "$group" -m "$mode" "$temporary" "$target"
      exit 3
    stdin: "{{{{ {role_name}_secrets[item.key] }}}}"
    stdin_add_newline: false
  register: {role_name}_file_secret_result
  changed_when: {role_name}_file_secret_result.rc == 3
  failed_when: {role_name}_file_secret_result.rc not in [0, 3]
  no_log: true
  loop:
{rendered_secrets}
  loop_control:
    label: "{{{{ item.path }}}}"

"""


def _render_meta(has_secrets: bool) -> str:
    collections = ["  - community.docker"]
    if has_secrets:
        collections.append("  - community.sops")
    return "\n".join(("---", "collections:", *collections, "dependencies: []", ""))


def _render_requirements(has_secrets: bool) -> str:
    collections = ["  - name: community.docker", "    version: 5.4.0"]
    if has_secrets:
        collections.extend(("  - name: community.sops", "    version: 2.5.0"))
    return "\n".join(("---", "collections:", *collections, ""))


def _render_provenance(
    project: ResolvedProject,
    role_name: str,
    prerequisites: tuple[tuple[str, str], ...],
    materialization: SourceRoleMaterialization,
) -> str:
    redacted_document = _redact_environment_values(project.canonical_document)
    canonical_json = json.dumps(redacted_document, sort_keys=True, separators=(",", ":"))
    config_files = list(project.project.config_files)
    source_root = str(project.source.root)
    provenance = {
        "external_prerequisites": [
            {"kind": kind, "name": name} for kind, name in prerequisites
        ],
        "files": _source_file_hashes(project, materialization),
        "generator": "compose2role",
        "mode": "remote",
        "project": project.project.name,
        "role": role_name,
        "source": {"config_files": config_files, "root": source_root},
        "structural_hash": hashlib.sha256(canonical_json.encode("utf-8")).hexdigest(),
        "version": version("compose2role"),
    }
    return json.dumps(provenance, indent=2, sort_keys=True) + "\n"


def _source_file_hashes(
    project: ResolvedProject, materialization: SourceRoleMaterialization
) -> dict[str, dict[str, object]]:
    secret_paths = {
        template.source.relative_path
        for template in materialization.templates
        if template.has_secrets
    }
    entries: dict[str, dict[str, object]] = {}
    for source in project.source.files:
        if source.relative_path in secret_paths:
            entries[str(source.relative_path)] = {
                "redacted": True,
                "sha256": normalized_compose_hash(source.content),
            }
        else:
            entries[str(source.relative_path)] = {
                "redacted": False,
                "sha256": hashlib.sha256(source.content).hexdigest(),
            }
    for source in project.source.dotenv_files:
        if source.relative_path in secret_paths:
            entries[str(source.relative_path)] = {
                "redacted": True,
                "sha256": normalized_dotenv_hash(source.content),
            }
        else:
            entries[str(source.relative_path)] = {
                "redacted": False,
                "sha256": hashlib.sha256(source.content).hexdigest(),
            }
    for file_secret in project.source.file_secrets:
        entries[str(file_secret.source.relative_path)] = {
            "redacted": True,
            "sha256": normalized_file_secret_hash(file_secret.source.metadata),
        }
    return entries


def normalized_compose_hash(content: bytes) -> str:
    try:
        document = YAML(typ="rt").load(content.decode("utf-8"))
    except (UnicodeDecodeError, YAMLError):
        return _hash_json({"redacted": "compose"})
    return _hash_json(_redact_environment_values(document))


def normalized_dotenv_hash(content: bytes) -> str:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return _hash_json({"redacted": "dotenv"})
    keys = [
        match.group(1)
        for line in text.splitlines()
        if (match := _DOTENV_KEY.match(line)) is not None
    ]
    return _hash_json({"dotenv_keys": keys})


def normalized_file_secret_hash(metadata: FileMetadata) -> str:
    return _hash_json(
        {
            "content": "<redacted-file-secret>",
            "gid": metadata.gid,
            "mode": metadata.mode,
            "uid": metadata.uid,
        }
    )


def _hash_json(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_DOTENV_KEY = re.compile(r"[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=")


def _redact_environment_values(value: object, *, redact_values: bool = False) -> object:
    if isinstance(value, dict):
        return {
            key: "<redacted-environment-value>"
            if redact_values
            else _redact_environment_values(item, redact_values=key == "environment")
            for key, item in value.items()
        }
    if isinstance(value, list):
        if redact_values:
            return ["<redacted-environment-value>" for _ in value]
        return [_redact_environment_values(item) for item in value]
    if redact_values:
        return "<redacted-environment-value>"
    return value


def external_prerequisites(document: dict[str, object]) -> tuple[tuple[str, str], ...]:
    """Return external Compose configs and secrets declared by the canonical model."""
    prerequisites: list[tuple[str, str]] = []
    for kind, key in (("config", "configs"), ("secret", "secrets")):
        value = document.get(key, {})
        definitions = _mapping(value, "remote Compose model has invalid external resources")
        for name, definition in definitions.items():
            definition_mapping = _mapping(
                definition, "remote Compose model has invalid external resources"
            )
            if definition_mapping.get("external") is True:
                prerequisites.append((kind, name))
    return tuple(prerequisites)


def _mapping(value: object, message: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise GenerationError(message)
    for key in value:
        if not isinstance(key, str):
            raise GenerationError(message)
    return value
