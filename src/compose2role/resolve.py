"""Shared project model, capture seam, and resolution pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal, Protocol

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError

from compose2role.discover import DiscoveredProject
from compose2role.errors import Compose2RoleError, ComposeParseError
from compose2role.findings import Finding, audit_stack, classified_secret_finding
from compose2role.model import Stack, parse_canonical_stack
from compose2role.secret_policy import SecretPolicy
from compose2role.secrets import EnvironmentClassification, classify_environment, is_secret_key
from compose2role.source import FileMetadata

_UNSUPPORTED_DOCUMENT_FEATURES = {
    "include": "C2R008: remote Compose include files are not supported",
}
_UNSUPPORTED_SERVICE_FEATURES = {
    "build": "C2R005: remote build contexts are not supported",
    "extends": "C2R006: remote service extends declarations are not supported",
    "profiles": "C2R007: remote service profiles are not supported",
}


@dataclass(frozen=True)
class SourceFile:
    """One raw, root-relative source file retained only in controller memory."""

    relative_path: PurePosixPath
    content: bytes = field(repr=False)
    metadata: FileMetadata


@dataclass(frozen=True)
class FileSecret:
    """One file-backed Compose secret retained only in controller memory."""

    name: str
    source: SourceFile = field(repr=False)


@dataclass(frozen=True)
class ProjectSnapshot:
    """An ordered source snapshot for a root-contained Compose project."""

    root: PurePosixPath
    files: tuple[SourceFile, ...] = field(repr=False)
    dotenv_files: tuple[SourceFile, ...] = field(default=(), repr=False)
    file_secrets: tuple[FileSecret, ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class ResolvedProject:
    """One project resolved to canonical and source-faithful representations."""

    project: DiscoveredProject
    stack: Stack
    canonical_document: dict[str, object]
    findings: tuple[Finding, ...]
    classifications: tuple[EnvironmentClassification, ...]
    source: ProjectSnapshot = field(repr=False)
    secret_policy: SecretPolicy | None = field(default=None, repr=False)
    drift: ProjectDrift | None = field(default=None, repr=False)

    def as_json(self) -> dict[str, object]:
        """Return the value-free audit JSON envelope for a successful project."""
        return {
            "classifications": [
                classification.as_json()
                for classification in self.classifications
                if classification.is_secret
            ],
            "drift": None if self.drift is None else self.drift.as_json(),
            "error": None,
            "findings": [finding.as_json() for finding in self.findings],
            "name": self.project.name,
            "role": None,
            "status": "ok",
        }


@dataclass(frozen=True)
class ProjectFailure:
    """A value-free operational failure for one project."""

    name: str
    category: str
    message: str

    def as_json(self) -> dict[str, object]:
        """Return the value-free audit JSON envelope for a failed project."""
        return {
            "classifications": [],
            "drift": None,
            "error": self.message,
            "findings": [],
            "name": self.name,
            "role": None,
            "status": "failed",
        }


type AuditOutcome = ResolvedProject | ProjectFailure


@dataclass(frozen=True)
class AuditResult:
    """Audit successes and isolated per-project failures."""

    projects: tuple[ResolvedProject, ...]
    failures: tuple[ProjectFailure, ...]
    outcomes: tuple[AuditOutcome, ...]

    def as_json(self) -> dict[str, list[dict[str, object]]]:
        """Return the batch JSON envelope used by audit."""
        return {"projects": [outcome.as_json() for outcome in self.outcomes]}


type DiffState = Literal["added", "changed", "unchanged", "withheld"]

type DriftState = Literal["unchanged", "source changed", "unmanaged", "missing"]


@dataclass(frozen=True)
class ProjectDrift:
    """The value-free drift state of one project against its generated role."""

    state: DriftState
    role: str
    changed: tuple[str, ...] = ()
    reason: str | None = None

    def as_json(self) -> dict[str, object]:
        """Return paths and reasons only, never source content."""
        payload: dict[str, object] = {
            "changed": list(self.changed),
            "role": self.role,
            "state": self.state,
        }
        if self.reason is not None:
            payload["reason"] = self.reason
        return payload


@dataclass(frozen=True)
class FileDiff:
    """One value-free comparison result for a planned role file."""

    path: str
    change: Literal["added", "changed", "unchanged"]
    withheld: bool = False
    withheld_reason: str | None = None
    old_text: str | None = field(default=None, repr=False)
    new_text: str | None = field(default=None, repr=False)

    @property
    def state(self) -> DiffState:
        """Return the reported state, preferring the withheld category."""
        if self.withheld and self.change != "unchanged":
            return "withheld"
        return self.change


@dataclass(frozen=True)
class PlanDiff:
    """The value-free difference between a rendered plan and an existing role."""

    role_exists: bool
    unmanaged: bool
    files: tuple[FileDiff, ...]

    @property
    def identical(self) -> bool:
        """Return whether every planned file is unchanged."""
        return self.role_exists and all(file.state == "unchanged" for file in self.files)

    def as_json(self) -> dict[str, list[str]]:
        """Return path-only diff categories; content is never included."""
        grouped: dict[str, list[str]] = {
            "added": [],
            "changed": [],
            "unchanged": [],
            "withheld": [],
        }
        for file in self.files:
            grouped[file.state].append(file.path)
        return grouped


@dataclass(frozen=True)
class GeneratedProject:
    """One project successfully generated or checked."""

    project: ResolvedProject
    role_name: str
    checked: bool
    files: tuple[str, ...]
    unchanged: bool = False
    diff: PlanDiff | None = None
    diff_only: bool = False

    @property
    def name(self) -> str:
        """Return the raw Compose project name."""
        return self.project.project.name

    def as_json(self) -> dict[str, object]:
        """Return a value-free generation summary for this project."""
        if self.checked:
            status = "checked"
        elif self.diff is not None and self.diff_only:
            status = "unchanged" if self.diff.identical else "diff"
        elif self.unchanged:
            status = "unchanged"
        else:
            status = "generated"
        summary: dict[str, object] = {
            "classifications": [
                classification.as_json()
                for classification in self.project.classifications
                if classification.is_secret
            ],
            "error": None,
            "findings": [finding.as_json() for finding in self.project.findings],
            "name": self.name,
            "role": self.role_name,
            "status": status,
        }
        if self.checked:
            summary["files"] = list(self.files)
        if self.diff is not None:
            summary["diff"] = self.diff.as_json()
        return summary


@dataclass(frozen=True)
class GenerationFailure:
    """A value-free generation failure for one project."""

    name: str
    role_name: str | None
    category: str
    message: str
    findings: tuple[Finding, ...] = ()
    classifications: tuple[EnvironmentClassification, ...] = ()

    def as_json(self) -> dict[str, object]:
        """Return a value-free generation summary for this failed project."""
        return {
            "classifications": [
                classification.as_json()
                for classification in self.classifications
                if classification.is_secret
            ],
            "error": self.message,
            "findings": [finding.as_json() for finding in self.findings],
            "name": self.name,
            "role": self.role_name,
            "status": "failed",
        }


type GenerationOutcome = GeneratedProject | GenerationFailure


@dataclass(frozen=True)
class GenerationResult:
    """Ordered generated and failed project outcomes."""

    outcomes: tuple[GenerationOutcome, ...]

    @property
    def failures(self) -> tuple[GenerationFailure, ...]:
        """Return every project that did not generate successfully."""
        return tuple(
            outcome for outcome in self.outcomes if isinstance(outcome, GenerationFailure)
        )

    def as_json(self) -> dict[str, list[dict[str, object]]]:
        """Return the generation batch envelope."""
        return {"projects": [outcome.as_json() for outcome in self.outcomes]}


class ProjectResolutionError(Compose2RoleError):
    """A value-free error while resolving a particular project."""

    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category


class ProjectCapture(Protocol):
    """A transport that captures root-contained source files."""

    def capture(self, root: PurePosixPath, path: PurePosixPath) -> SourceFile | str:
        """Capture PATH and its metadata, or return its source-boundary state."""
        ...

    def stat(self, root: PurePosixPath, path: PurePosixPath) -> str:
        """Return the source-boundary state of PATH without reading its bytes."""
        ...

    def close(self) -> None:
        """Finish the capture session."""
        ...

    def abort(self) -> None:
        """Discard the capture session without replacing the original error."""
        ...


@dataclass(frozen=True)
class CanonicalResult:
    """The effective Compose document plus an optional source-located typed stack."""

    document: dict[str, object]
    stack: Stack | None = None


class Canonicalizer(Protocol):
    """A transport that produces the effective Compose document."""

    def canonicalize(
        self,
        identity: DiscoveredProject,
        root: PurePosixPath,
        files: tuple[PurePosixPath, ...],
    ) -> CanonicalResult:
        """Return the canonical Compose document for the captured project."""
        ...


@dataclass(frozen=True)
class _EnvironmentFile:
    """A service env_file reference that must remain within the project root."""

    path: PurePosixPath
    required: bool


@dataclass(frozen=True)
class _FileSecretInput:
    """A contained source file referenced by one Compose secret declaration."""

    name: str
    path: PurePosixPath


def resolve_project(
    capture: ProjectCapture,
    canonicalizer: Canonicalizer,
    identity: DiscoveredProject,
    secret_policy: SecretPolicy | None,
    *,
    extra_dotenv_paths: tuple[PurePosixPath, ...] = (),
) -> ResolvedProject:
    """Capture, canonicalize, classify, and audit one root-contained project."""
    root = project_root(identity)
    try:
        source = _capture_source_snapshot(capture, identity, root)
        source_documents = _source_documents(source)
        _validate_source_documents(source_documents)
        environment_files = _environment_files(source_documents, root)
        dotenv_files, file_secrets = _capture_dependent_inputs(
            capture,
            root,
            environment_files,
            _file_secret_inputs(source_documents, root),
            extra_dotenv_paths,
        )
    except Exception:
        capture.abort()
        raise
    else:
        capture.close()
    source = ProjectSnapshot(
        root=source.root,
        files=source.files,
        dotenv_files=dotenv_files,
        file_secrets=file_secrets,
    )
    canonical = canonicalizer.canonicalize(
        identity, root, tuple(file.relative_path for file in source.files)
    )
    canonical_document = canonical.document
    if canonical.stack is not None:
        stack = canonical.stack
    else:
        try:
            stack = parse_canonical_stack(
                canonical_document,
                source_path=PurePosixPath("remote-compose.json"),
            )
        except ComposeParseError as error:
            raise ProjectResolutionError(
                "invalid-model", "remote Docker Compose returned an unsupported effective model"
            ) from error
        _validate_canonical_topology(canonical_document)
    classifications = tuple(
        classify_environment(
            identity.name,
            service.name,
            environment.name,
            environment.value,
            environment.location,
            secret_policy,
        )
        for service in stack.services
        for environment in service.environment
    )
    inline_secret_entries = {
        (service.name, environment.name)
        for service in stack.services
        for environment in service.environment
        if environment.is_secret
    }
    findings = (
        *audit_stack(stack),
        *(
            classified_secret_finding(
                classification.service,
                classification.key,
                classification.reason,
                classification.location,
            )
            for classification in classifications
            if classification.is_secret
            and (classification.service, classification.key) not in inline_secret_entries
        ),
    )
    return ResolvedProject(
        project=identity,
        stack=stack,
        canonical_document=canonical_document,
        findings=findings,
        classifications=classifications,
        source=source,
        secret_policy=secret_policy,
    )


def project_root(project: DiscoveredProject) -> PurePosixPath:
    """Return the root that contains every declared Compose file."""
    if not project.config_files:
        raise ProjectResolutionError("source", "the remote project has no Compose files")
    _safe_line(project.name, "project name")
    config_files = tuple(_safe_remote_path(path) for path in project.config_files)
    if len(project.working_directories) > 1:
        raise ProjectResolutionError(
            "source", "remote Compose project has conflicting working-directory labels"
        )
    root = (
        _safe_project_root(project.working_directories[0])
        if project.working_directories
        else config_files[0].parent
    )
    for path in config_files:
        relative_source_path(root, path)
    return root


def _validate_canonical_topology(document: dict[str, object]) -> None:
    services = _canonical_mapping(
        document.get("services"), "remote Docker Compose returned an unsupported effective model"
    )
    for service in services.values():
        service_mapping = _canonical_mapping(
            service, "remote Docker Compose returned an unsupported effective model"
        )
        _canonical_volumes(service_mapping)


def _canonical_volumes(service: dict[str, object]) -> tuple[dict[str, object], ...]:
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        raise ProjectResolutionError(
            "invalid-model", "remote Docker Compose returned an unsupported effective model"
        )
    return tuple(
        _canonical_mapping(
            volume, "remote Docker Compose returned an unsupported effective model"
        )
        for volume in volumes
    )


def _canonical_mapping(value: object, message: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProjectResolutionError("invalid-model", message)
    mapping: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ProjectResolutionError("invalid-model", message)
        mapping[key] = item
    return mapping


def _safe_remote_path(path: str) -> PurePosixPath:
    _safe_line(path, "Compose file path")
    parsed_path = PurePosixPath(path)
    if not parsed_path.is_absolute():
        raise ProjectResolutionError("source", "remote Compose file paths must be absolute")
    if ".." in parsed_path.parts:
        raise ProjectResolutionError("source", "remote Compose file path escapes the project root")
    return parsed_path


def _safe_project_root(path: str) -> PurePosixPath:
    _safe_line(path, "Compose project working directory")
    parsed_path = PurePosixPath(path)
    if not parsed_path.is_absolute():
        raise ProjectResolutionError(
            "source", "remote Compose project working directory must be absolute"
        )
    if ".." in parsed_path.parts:
        raise ProjectResolutionError(
            "source", "remote Compose project working directory escapes the project root"
        )
    return parsed_path


def _safe_line(value: str, description: str) -> None:
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ProjectResolutionError(
            "source", f"remote {description} contains unsupported characters"
        )


def relative_source_path(root: PurePosixPath, path: PurePosixPath) -> PurePosixPath:
    """Return PATH relative to ROOT, rejecting an escape."""
    try:
        return path.relative_to(root)
    except ValueError as error:
        raise ProjectResolutionError(
            "source", "remote Compose file path escapes the project root"
        ) from error


def _capture_source_snapshot(
    capture: ProjectCapture,
    project: DiscoveredProject,
    root: PurePosixPath,
) -> ProjectSnapshot:
    paths = tuple(_safe_remote_path(path) for path in project.config_files)
    files = tuple(_required_source_file(capture.capture(root, path)) for path in paths)
    return ProjectSnapshot(root=root, files=files)


def _required_source_file(capture: SourceFile | str) -> SourceFile:
    if isinstance(capture, SourceFile):
        return capture
    if capture == "escape":
        raise ProjectResolutionError("source", "remote Compose file path escapes the project root")
    if capture == "symlink":
        raise ProjectResolutionError("source", "remote Compose source file must not be a symlink")
    raise ProjectResolutionError("source", "remote Compose source file is not a regular file")


def _captured_input_file(capture: SourceFile | str, message: str) -> SourceFile:
    if isinstance(capture, SourceFile):
        return capture
    raise ProjectResolutionError("source", message)


def _source_documents(source: ProjectSnapshot) -> tuple[dict[str, object], ...]:
    documents: list[dict[str, object]] = []
    for file in source.files:
        try:
            document: object = YAML(typ="rt").load(file.content.decode("utf-8"))
        except (UnicodeDecodeError, YAMLError) as error:
            raise ProjectResolutionError(
                "source", "remote Compose source could not be parsed safely"
            ) from error
        _validate_source_tags(document)
        documents.append(_source_mapping(document))
    return tuple(documents)


def _source_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProjectResolutionError("source", "remote Compose source must be a mapping")
    mapping: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ProjectResolutionError(
                "source", "remote Compose source has invalid mapping keys"
            )
        mapping[key] = item
    return mapping


def _validate_source_tags(value: object) -> None:
    tag = getattr(value, "tag", None)
    tag_value = getattr(tag, "value", None)
    if tag_value is not None and (
        tag_value not in {"!override", "!reset"}
        or not isinstance(value, (CommentedMap, CommentedSeq))
    ):
        raise ProjectResolutionError(
            "source", "remote Compose source has an unsupported YAML tag"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_source_tags(key)
            _validate_source_tags(item)
    elif isinstance(value, list):
        for item in value:
            _validate_source_tags(item)


def _environment_files(
    documents: tuple[dict[str, object], ...], root: PurePosixPath
) -> tuple[_EnvironmentFile, ...]:
    environment_files: list[_EnvironmentFile] = []
    for document in documents:
        services = _source_mapping(document.get("services", {}))
        for service in services.values():
            service_mapping = _source_mapping(service)
            if "env_file" not in service_mapping:
                continue
            environment_files.extend(
                _parse_environment_files(service_mapping["env_file"], root)
            )
    return tuple(environment_files)


def _validate_source_documents(documents: tuple[dict[str, object], ...]) -> None:
    for document in documents:
        for feature, message in _UNSUPPORTED_DOCUMENT_FEATURES.items():
            if feature in document:
                raise ProjectResolutionError("source", message)
        _validate_file_backed_configs(document)
        _reject_non_environment_secret_mapping_keys(document)
        services = _source_mapping(document.get("services", {}))
        for service in services.values():
            service_mapping = _source_mapping(service)
            for feature, message in _UNSUPPORTED_SERVICE_FEATURES.items():
                if feature in service_mapping:
                    raise ProjectResolutionError("source", message)


def _validate_file_backed_configs(document: dict[str, object]) -> None:
    definitions = _source_mapping(document.get("configs", {}))
    for definition in definitions.values():
        definition_mapping = _source_mapping(definition)
        if "file" in definition_mapping:
            raise ProjectResolutionError(
                "topology", "C2R027: remote file-backed Compose configs are not supported"
            )


def _reject_non_environment_secret_mapping_keys(document: dict[str, object]) -> None:
    _walk_source_mappings(document, scan_keys=False)


def _walk_source_mappings(value: object, *, scan_keys: bool) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProjectResolutionError(
                    "source", "remote Compose source has invalid mapping keys"
                )
            if scan_keys and is_secret_key(key):
                raise ProjectResolutionError(
                    "topology",
                    "C2R029: remote non-environment secret-shaped mapping keys are not supported",
                )
            if key == "environment":
                continue
            if key in {"services", "configs", "secrets", "networks", "volumes", "depends_on"}:
                _walk_source_identity_mapping(item)
            else:
                _walk_source_mappings(item, scan_keys=True)
    elif isinstance(value, list):
        for item in value:
            _walk_source_mappings(item, scan_keys=scan_keys)


def _walk_source_identity_mapping(value: object) -> None:
    if not isinstance(value, dict):
        _walk_source_mappings(value, scan_keys=True)
        return
    for key, item in value.items():
        if not isinstance(key, str):
            raise ProjectResolutionError(
                "source", "remote Compose source has invalid mapping keys"
            )
        _walk_source_mappings(item, scan_keys=False)


def _parse_environment_files(value: object, root: PurePosixPath) -> tuple[_EnvironmentFile, ...]:
    if isinstance(value, (str, dict)):
        values: list[object] = [value]
    elif isinstance(value, list):
        values = value
    else:
        raise ProjectResolutionError("source", "remote service env_file entries are invalid")

    environment_files: list[_EnvironmentFile] = []
    for item in values:
        required = True
        if isinstance(item, str):
            reference = item
        elif isinstance(item, dict):
            item_mapping = _source_mapping(item)
            reference_value = item_mapping.get("path")
            required_value = item_mapping.get("required", True)
            if not isinstance(reference_value, str) or not isinstance(required_value, bool):
                raise ProjectResolutionError(
                    "source", "remote service env_file entries are invalid"
                )
            reference = reference_value
            required = required_value
        else:
            raise ProjectResolutionError("source", "remote service env_file entries are invalid")
        environment_files.append(_EnvironmentFile(_contained_path(root, reference), required))
    return tuple(environment_files)


def _contained_path(
    root: PurePosixPath, reference: str, *, subject: str = "environment file"
) -> PurePosixPath:
    _safe_line(reference, f"{subject} path")
    relative_path = PurePosixPath(reference)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ProjectResolutionError("source", f"remote {subject} path escapes the project root")
    path = root.joinpath(*relative_path.parts)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ProjectResolutionError(
            "source", f"remote {subject} path escapes the project root"
        ) from error
    return path


def _file_secret_inputs(
    documents: tuple[dict[str, object], ...], root: PurePosixPath
) -> tuple[_FileSecretInput, ...]:
    inputs: list[_FileSecretInput] = []
    for document in documents:
        definitions = _source_mapping(document.get("secrets", {}))
        for name, definition in definitions.items():
            if not isinstance(name, str) or not name:
                raise ProjectResolutionError("source", "remote Compose secret names are invalid")
            definition_mapping = _source_mapping(definition)
            file_value = definition_mapping.get("file")
            if file_value is None:
                continue
            if not isinstance(file_value, str) or not file_value:
                raise ProjectResolutionError(
                    "source", "remote file-backed Compose secret input is invalid"
                )
            inputs.append(
                _FileSecretInput(
                    name=name,
                    path=_contained_path(
                        root, file_value, subject="file-backed Compose secret"
                    ),
                )
            )
    return tuple(inputs)


def _capture_dependent_inputs(
    capture: ProjectCapture,
    root: PurePosixPath,
    environment_files: tuple[_EnvironmentFile, ...],
    secret_inputs: tuple[_FileSecretInput, ...],
    extra_dotenv_paths: tuple[PurePosixPath, ...],
) -> tuple[tuple[SourceFile, ...], tuple[FileSecret, ...]]:
    root_dotenv_path = root / ".env"
    dotenv_files: list[SourceFile] = []
    captured_dotenv_paths: set[PurePosixPath] = set()
    root_dotenv_state = capture.stat(root, root_dotenv_path)
    if root_dotenv_state == "file":
        dotenv_files.append(
            _captured_input_file(
                capture.capture(root, root_dotenv_path),
                "remote root dotenv input is not a regular file",
            )
        )
        captured_dotenv_paths.add(root_dotenv_path)
    elif root_dotenv_state == "escape":
        raise ProjectResolutionError(
            "source", "remote environment file path escapes the project root"
        )
    elif root_dotenv_state != "missing":
        raise ProjectResolutionError("source", "remote root dotenv input is not a regular file")

    for extra_path in extra_dotenv_paths:
        absolute_path = root.joinpath(*extra_path.parts)
        if absolute_path in captured_dotenv_paths:
            continue
        state = capture.stat(root, absolute_path)
        if state == "file":
            dotenv_files.append(
                _captured_input_file(
                    capture.capture(root, absolute_path),
                    "remote environment file input is not a regular file",
                )
            )
            captured_dotenv_paths.add(absolute_path)
            continue
        if state == "escape":
            raise ProjectResolutionError(
                "source", "remote environment file path escapes the project root"
            )
        raise ProjectResolutionError(
            "source", "remote environment file input is not a regular file"
        )

    for environment_file in environment_files:
        state = capture.stat(root, environment_file.path)
        if state == "file":
            if environment_file.path not in captured_dotenv_paths:
                dotenv_files.append(
                    _captured_input_file(
                        capture.capture(root, environment_file.path),
                        "remote service env_file input is not a regular file",
                    )
                )
                captured_dotenv_paths.add(environment_file.path)
            continue
        if state == "escape":
            raise ProjectResolutionError(
                "source", "remote environment file path escapes the project root"
            )
        if state == "missing" and not environment_file.required:
            continue
        raise ProjectResolutionError(
            "source", "remote service env_file input is not a regular file"
        )

    file_secrets: list[FileSecret] = []
    for secret_input in secret_inputs:
        state = capture.stat(root, secret_input.path)
        if state == "file":
            file_secrets.append(
                FileSecret(
                    name=secret_input.name,
                    source=_captured_input_file(
                        capture.capture(root, secret_input.path),
                        "remote file-backed Compose secret input is not a regular file",
                    ),
                )
            )
            continue
        if state == "escape":
            raise ProjectResolutionError(
                "source", "remote file-backed Compose secret path escapes the project root"
            )
        raise ProjectResolutionError(
            "source", "remote file-backed Compose secret input is not a regular file"
        )
    return tuple(dotenv_files), tuple(file_secrets)
