"""Prepare source-faithful remote Compose templates and parameter values."""

from __future__ import annotations

import hashlib
import re
from base64 import b64encode
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError

from compose2role.errors import GenerationError
from compose2role.model import Port, Service, SourcePosition
from compose2role.resolve import ResolvedProject, SourceFile
from compose2role.secret_policy import SecretPolicy
from compose2role.secrets import classify_environment


@dataclass(frozen=True)
class SourceTemplate:
    """One source file rendered through Ansible without normalizing its layout."""

    source: SourceFile
    content: str
    newline_sequence: str
    has_secrets: bool = False

    @property
    def relative_template_path(self) -> PurePosixPath:
        """Return the role-relative template path for the captured source file."""
        return self.source.relative_path.with_name(f"{self.source.relative_path.name}.j2")


@dataclass(frozen=True)
class RoleVariable:
    """One generated default or encrypted SOPS value."""

    name: str
    value: str = field(repr=False)
    is_secret: bool


@dataclass(frozen=True)
class FileSecretRender:
    """One encrypted file-backed secret restored by the generated role."""

    compose_secret_name: str
    source: SourceFile = field(repr=False)
    variable_name: str


@dataclass(frozen=True)
class SourceRoleMaterialization:
    """The source templates and values needed to render one adopted role."""

    templates: tuple[SourceTemplate, ...]
    variables: tuple[RoleVariable, ...] = field(repr=False)
    file_secrets: tuple[FileSecretRender, ...] = field(default=(), repr=False)

    @property
    def secret_values(self) -> dict[str, str]:
        """Return the in-memory SOPS payload without exposing it through repr()."""
        return {variable.name: variable.value for variable in self.variables if variable.is_secret}


@dataclass(frozen=True)
class _Candidate:
    """A source value which becomes one role variable."""

    identity: str
    base_name: str
    value: str = field(repr=False)
    is_secret: bool


@dataclass(frozen=True)
class _Edit:
    """One source span replaced by text and generated variables."""

    start: int
    end: int
    parts: tuple[str | _Candidate, ...]


def materialize_source_role(
    project: ResolvedProject, role_name: str
) -> SourceRoleMaterialization:
    """Build byte-faithful templates and parameter values for captured Compose files.

    The public remote emitter consumes this one result.  Parsing, source-span tracking, collision
    handling, and Jinja escaping stay local so callers only need the emitted templates and values.
    """
    candidates: dict[str, _Candidate] = {}
    edits_by_path: dict[PurePosixPath, list[_Edit]] = {}
    file_secret_candidates: list[tuple[str, SourceFile, _Candidate]] = []
    dotenv_environment_decisions: dict[str, set[bool]] = {}
    services = {service.name: service for service in project.stack.services}
    canonical_secret_classifications = {
        (classification.service, classification.key): classification.is_secret
        for classification in project.classifications
    }

    for source in project.source.files:
        content = _decode_source(source)
        document = _load_round_trip_document(content)
        _raise_for_extension_secret_environments(
            document, source.relative_path, project.project.name, project.secret_policy
        )
        source_edits = edits_by_path.setdefault(source.relative_path, [])
        source_services = _mapping(
            document.get("services"), "remote Compose source has invalid services"
        )
        for service_name, source_service in source_services.items():
            if not isinstance(service_name, str):
                raise GenerationError("remote Compose source has invalid service names")
            service_mapping = _mapping(
                source_service, "remote Compose source has an invalid service"
            )
            service = services.get(service_name)
            if service is None:
                _raise_for_source_only_secret_environment(
                    service_mapping.get("environment"),
                    service_name,
                    source.relative_path,
                    project.project.name,
                    project.secret_policy,
                )
                continue
            _plan_image_edit(
                candidates,
                source_edits,
                content,
                source.relative_path,
                service_mapping,
                service,
                role_name,
            )
            _plan_port_edits(
                candidates,
                source_edits,
                content,
                source.relative_path,
                service_mapping,
                service,
                role_name,
            )
            _plan_environment_edits(
                candidates,
                source_edits,
                content,
                source.relative_path,
                service_mapping,
                service,
                role_name,
                project.project.name,
                project.secret_policy,
                canonical_secret_classifications,
            )
            _record_dotenv_environment_decisions(
                service_mapping,
                service,
                source.relative_path,
                project.project.name,
                project.secret_policy,
                canonical_secret_classifications,
                dotenv_environment_decisions,
            )

    for source in project.source.dotenv_files:
        content = _decode_source(source)
        source_edits = edits_by_path.setdefault(source.relative_path, [])
        _plan_dotenv_edits(
            candidates,
            source_edits,
            content,
            source.relative_path,
            project.project.name,
            role_name,
            project.secret_policy,
            dotenv_environment_decisions,
        )

    for file_secret in project.source.file_secrets:
        candidate = _add_candidate(
            candidates,
            identity=f"file-secret:{file_secret.name}:{file_secret.source.relative_path}",
            base_name=f"{role_name}_secret_{_normalize_name(file_secret.name)}",
            value=b64encode(file_secret.source.content).decode("ascii"),
            is_secret=True,
        )
        file_secret_candidates.append((file_secret.name, file_secret.source, candidate))

    names = _variable_names(
        candidates.values(),
        {
            f"{role_name}_compose_project_name",
            f"{role_name}_project_dir",
            f"{role_name}_required_secrets",
            f"{role_name}_secrets_file",
        },
    )
    source_files = (*project.source.files, *project.source.dotenv_files)
    templates = tuple(
        SourceTemplate(
            source=source,
            content=_apply_edits(
                _decode_source(source), edits_by_path[source.relative_path], names, role_name
            ),
            newline_sequence=_newline_sequence(_decode_source(source)),
            has_secrets=any(
                isinstance(part, _Candidate) and part.is_secret
                for edit in edits_by_path[source.relative_path]
                for part in edit.parts
            ),
        )
        for source in source_files
    )
    variables = tuple(
        RoleVariable(
            name=names[candidate.identity],
            value=candidate.value,
            is_secret=candidate.is_secret,
        )
        for candidate in candidates.values()
    )
    file_secrets = tuple(
        FileSecretRender(
            compose_secret_name=name,
            source=source,
            variable_name=names[candidate.identity],
        )
        for name, source, candidate in file_secret_candidates
    )
    return SourceRoleMaterialization(
        templates=templates,
        variables=variables,
        file_secrets=file_secrets,
    )


def _decode_source(source: SourceFile) -> str:
    try:
        return source.content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GenerationError("remote Compose source must be UTF-8") from error


def _load_round_trip_document(content: str) -> CommentedMap:
    yaml = YAML(typ="rt")
    try:
        document: object = yaml.load(content)
    except YAMLError as error:
        raise GenerationError("remote Compose source could not be parsed") from error
    return _mapping(document, "remote Compose source must be a mapping")


def _mapping(value: object, message: str) -> CommentedMap:
    if not isinstance(value, CommentedMap):
        raise GenerationError(message)
    return value


def _plan_image_edit(
    candidates: dict[str, _Candidate],
    edits: list[_Edit],
    content: str,
    relative_path: PurePosixPath,
    source_service: CommentedMap,
    service: Service,
    role_name: str,
) -> None:
    source_image = source_service.get("image")
    if not isinstance(source_image, str) or "$" in source_image:
        return
    repository, reference, separator = _image_parts(service)
    if source_image != service.image.source:
        return
    try:
        start, end = _value_span(content, source_service, "image")
    except GenerationError:
        return
    prefix, suffix = _scalar_wrapper(content[start:end])
    identity_prefix = f"compose:{relative_path}:{service.name}:image"
    image = _add_candidate(
        candidates,
        identity=f"{identity_prefix}:repository",
        base_name=f"{_service_prefix(role_name, service)}_image",
        value=repository,
        is_secret=False,
    )
    if source_image == repository and reference == "latest" and separator == ":":
        edits.append(_Edit(start, end, (prefix, image, suffix)))
        return
    tag = _add_candidate(
        candidates,
        identity=f"{identity_prefix}:reference",
        base_name=f"{_service_prefix(role_name, service)}_image_tag",
        value=reference,
        is_secret=False,
    )
    edits.append(_Edit(start, end, (prefix, image, separator, tag, suffix)))


def _plan_port_edits(
    candidates: dict[str, _Candidate],
    edits: list[_Edit],
    content: str,
    relative_path: PurePosixPath,
    source_service: CommentedMap,
    service: Service,
    role_name: str,
) -> None:
    if not _has_direct_source_value(source_service, "ports"):
        return
    ports_value = source_service.get("ports")
    if not isinstance(ports_value, CommentedSeq):
        return
    published_ports = [port for port in service.ports if port.published is not None]
    used: set[int] = set()
    for source_index, source_port in enumerate(ports_value):
        try:
            source_item_span = _item_span(content, ports_value, source_index)
        except GenerationError:
            continue
        if isinstance(source_port, CommentedMap):
            parsed_long = _long_port(source_port)
            if parsed_long is None:
                continue
            published, target = parsed_long
            canonical_index = _matching_port(service.ports, published, target, used)
            if canonical_index is None:
                continue
            used.add(canonical_index)
            port = service.ports[canonical_index]
            if port.published is None:
                continue
            try:
                start, end = _value_span(content, source_port, "published")
            except GenerationError:
                continue
            raw = content[start:end]
            prefix, suffix = _scalar_wrapper(raw)
            value = raw[len(prefix) : len(raw) - len(suffix)] if prefix else raw
            published_index = published_ports.index(port) + 1
            variable = _add_candidate(
                candidates,
                identity=(
                    f"compose:{relative_path}:{service.name}:port:{source_index}:published"
                ),
                base_name=_published_port_variable(
                    _service_prefix(role_name, service), published_index, len(published_ports)
                ),
                value=value,
                is_secret=False,
            )
            edits.append(
                _Edit(start, end, (variable,) if not prefix else (prefix, variable, suffix))
            )
            continue
        if not isinstance(source_port, str):
            continue
        parsed = _short_port(source_port)
        if parsed is None:
            continue
        published, target = parsed
        canonical_index = _matching_port(service.ports, published, target, used)
        if canonical_index is None:
            continue
        used.add(canonical_index)
        port = service.ports[canonical_index]
        if port.published is None:
            continue
        start, end = source_item_span
        published_start, published_end = _short_port_published_span(
            content, start, end, published
        )
        published_index = published_ports.index(port) + 1
        variable = _add_candidate(
            candidates,
            identity=(
                f"compose:{relative_path}:{service.name}:port:{source_index}:published"
            ),
            base_name=_published_port_variable(
                _service_prefix(role_name, service), published_index, len(published_ports)
            ),
            value=published,
            is_secret=False,
        )
        edits.append(_Edit(published_start, published_end, (variable,)))


def _plan_environment_edits(
    candidates: dict[str, _Candidate],
    edits: list[_Edit],
    content: str,
    relative_path: PurePosixPath,
    source_service: CommentedMap,
    service: Service,
    role_name: str,
    project_name: str,
    secret_policy: SecretPolicy | None,
    canonical_secret_classifications: dict[tuple[str, str], bool],
) -> None:
    environment_value = source_service.get("environment")
    _raise_for_merged_secret_environment(
        source_service,
        service,
        relative_path,
        project_name,
        secret_policy,
        canonical_secret_classifications,
    )
    if not _has_direct_source_value(source_service, "environment"):
        _raise_for_uneditable_secret_environment(
            environment_value,
            service,
            relative_path,
            project_name,
            secret_policy,
            canonical_secret_classifications,
        )
        return
    if isinstance(environment_value, CommentedMap):
        _plan_mapping_environment_edits(
            candidates,
            edits,
            content,
            relative_path,
            environment_value,
            service,
            role_name,
            project_name,
            secret_policy,
            canonical_secret_classifications,
        )
        return
    if isinstance(environment_value, CommentedSeq):
        _plan_list_environment_edits(
            candidates,
            edits,
            content,
            relative_path,
            environment_value,
            service,
            role_name,
            project_name,
            secret_policy,
            canonical_secret_classifications,
        )


def _raise_for_merged_secret_environment(
    source_service: CommentedMap,
    service: Service,
    relative_path: PurePosixPath,
    project_name: str,
    secret_policy: SecretPolicy | None,
    canonical_secret_classifications: dict[tuple[str, str], bool],
) -> None:
    for merged_service in source_service.merge:
        if isinstance(merged_service, CommentedMap):
            _raise_for_uneditable_secret_environment(
                merged_service.get("environment"),
                service,
                relative_path,
                project_name,
                secret_policy,
                canonical_secret_classifications,
            )


def _raise_for_uneditable_secret_environment(
    environment: object,
    service: Service,
    relative_path: PurePosixPath,
    project_name: str,
    secret_policy: SecretPolicy | None,
    canonical_secret_classifications: dict[tuple[str, str], bool],
) -> None:
    if _environment_contains_secret_literal(
        environment,
        service,
        relative_path,
        project_name,
        secret_policy,
        canonical_secret_classifications,
    ):
        raise GenerationError("remote Compose source has an unsupported secret environment")


def _environment_contains_secret_literal(
    environment: object,
    service: Service,
    relative_path: PurePosixPath,
    project_name: str,
    secret_policy: SecretPolicy | None,
    canonical_secret_classifications: dict[tuple[str, str], bool],
) -> bool:
    if isinstance(environment, CommentedMap):
        return any(
            isinstance(key, str)
            and _is_secret_literal(value)
            and _source_environment_secret(
                service,
                key,
                value,
                _mapping_source_position(environment, key, relative_path),
                project_name,
                secret_policy,
                canonical_secret_classifications,
            )
            for key, value in environment.items()
        )
    if isinstance(environment, CommentedSeq):
        for index, item in enumerate(environment):
            if not isinstance(item, str):
                continue
            key, separator, value = item.partition("=")
            if (
                separator
                and _is_secret_literal(value)
                and _source_environment_secret(
                    service,
                    key,
                    value,
                    _sequence_source_position(environment, index, relative_path),
                    project_name,
                    secret_policy,
                    canonical_secret_classifications,
                )
            ):
                return True
    return False


def _is_secret_literal(value: object) -> bool:
    return value is not None and value != "" and (
        not isinstance(value, str) or not _uses_interpolation(value)
    )


def _raise_for_source_only_secret_environment(
    environment: object,
    service_name: str,
    relative_path: PurePosixPath,
    project_name: str,
    secret_policy: SecretPolicy | None,
) -> None:
    if isinstance(environment, CommentedMap):
        contains_secret = any(
            isinstance(key, str)
            and _is_secret_literal(value)
            and _source_environment_secret_for_service(
                service_name,
                key,
                value,
                _mapping_source_position(environment, key, relative_path),
                project_name,
                secret_policy,
                {},
            )
            for key, value in environment.items()
        )
    elif isinstance(environment, CommentedSeq):
        contains_secret = any(
            isinstance(item, str)
            and bool(separator)
            and _is_secret_literal(value)
            and _source_environment_secret_for_service(
                service_name,
                key,
                value,
                _sequence_source_position(environment, index, relative_path),
                project_name,
                secret_policy,
                {},
            )
            for index, item in enumerate(environment)
            for key, separator, value in (item.partition("="),)
        )
    else:
        contains_secret = False
    if contains_secret:
        raise GenerationError("remote Compose source has an unsupported secret environment")


def _raise_for_extension_secret_environments(
    document: CommentedMap,
    relative_path: PurePosixPath,
    project_name: str,
    secret_policy: SecretPolicy | None,
) -> None:
    for key, value in document.items():
        if isinstance(key, str) and key.startswith("x-"):
            _raise_for_nested_extension_secret_environments(
                value, relative_path, project_name, secret_policy
            )


def _raise_for_nested_extension_secret_environments(
    value: object,
    relative_path: PurePosixPath,
    project_name: str,
    secret_policy: SecretPolicy | None,
) -> None:
    if isinstance(value, CommentedMap):
        if "environment" in value:
            _raise_for_source_only_secret_environment(
                value["environment"], "extension", relative_path, project_name, secret_policy
            )
        for key, item in value.items():
            if key != "environment":
                _raise_for_nested_extension_secret_environments(
                    item, relative_path, project_name, secret_policy
                )
    elif isinstance(value, CommentedSeq):
        for item in value:
            _raise_for_nested_extension_secret_environments(
                item, relative_path, project_name, secret_policy
            )


def _source_environment_secret(
    service: Service,
    key: str,
    value: object,
    location: SourcePosition,
    project_name: str,
    secret_policy: SecretPolicy | None,
    canonical_secret_classifications: dict[tuple[str, str], bool],
) -> bool:
    return _source_environment_secret_for_service(
        service.name,
        key,
        value,
        location,
        project_name,
        secret_policy,
        canonical_secret_classifications,
    )


def _source_environment_secret_for_service(
    service_name: str,
    key: str,
    value: object,
    location: SourcePosition,
    project_name: str,
    secret_policy: SecretPolicy | None,
    canonical_secret_classifications: dict[tuple[str, str], bool],
) -> bool:
    source_classification = classify_environment(
        project_name,
        service_name,
        key,
        str(value),
        location,
        secret_policy,
    )
    return source_classification.is_secret or canonical_secret_classifications.get(
        (service_name, key), False
    )


def _mapping_source_position(
    mapping: CommentedMap, key: str, relative_path: PurePosixPath
) -> SourcePosition:
    return _source_position(mapping.lc.value(key), relative_path)


def _sequence_source_position(
    sequence: CommentedSeq, index: int, relative_path: PurePosixPath
) -> SourcePosition:
    return _source_position(sequence.lc.item(index), relative_path)


def _source_position(
    position: tuple[int, int] | None, relative_path: PurePosixPath
) -> SourcePosition:
    if position is None:
        return SourcePosition(relative_path, 1, 1)
    line, column = position
    return SourcePosition(relative_path, line + 1, column + 1)


def _plan_mapping_environment_edits(
    candidates: dict[str, _Candidate],
    edits: list[_Edit],
    content: str,
    relative_path: PurePosixPath,
    environment: CommentedMap,
    service: Service,
    role_name: str,
    project_name: str,
    secret_policy: SecretPolicy | None,
    canonical_secret_classifications: dict[tuple[str, str], bool],
) -> None:
    for key, value in environment.items():
        if not isinstance(key, str) or value is None:
            continue
        is_secret = _source_environment_secret(
            service,
            key,
            value,
            _mapping_source_position(environment, key, relative_path),
            project_name,
            secret_policy,
            canonical_secret_classifications,
        )
        if isinstance(value, str) and _uses_interpolation(value):
            continue
        if not isinstance(value, (str, int, float, bool)):
            if is_secret:
                raise GenerationError("remote Compose source has an unsupported secret environment")
            continue
        try:
            start, end = _value_span(content, environment, key)
        except GenerationError:
            if is_secret:
                raise
            continue
        raw = content[start:end]
        prefix, suffix = _scalar_wrapper(raw)
        value = raw[len(prefix) : len(raw) - len(suffix)] if prefix else raw
        variable = _add_candidate(
            candidates,
            identity=f"compose:{relative_path}:{service.name}:environment:{key}",
            base_name=f"{_service_prefix(role_name, service)}_{_normalize_name(key)}",
            value=value,
            is_secret=is_secret,
        )
        edits.append(
            _Edit(start, end, (variable,) if not prefix else (prefix, variable, suffix))
        )


def _plan_list_environment_edits(
    candidates: dict[str, _Candidate],
    edits: list[_Edit],
    content: str,
    relative_path: PurePosixPath,
    environment: CommentedSeq,
    service: Service,
    role_name: str,
    project_name: str,
    secret_policy: SecretPolicy | None,
    canonical_secret_classifications: dict[tuple[str, str], bool],
) -> None:
    for index, item in enumerate(environment):
        if not isinstance(item, str):
            continue
        key, separator, value = item.partition("=")
        if not key or not separator or _uses_interpolation(value):
            continue
        is_secret = _source_environment_secret(
            service,
            key,
            value,
            _sequence_source_position(environment, index, relative_path),
            project_name,
            secret_policy,
            canonical_secret_classifications,
        )
        try:
            start, end = _item_span(content, environment, index)
            value_start, value_end = _list_environment_value_span(content, start, end, key)
        except GenerationError:
            if is_secret:
                raise
            continue
        raw = content[value_start:value_end]
        prefix, suffix = _scalar_wrapper(raw)
        value = raw[len(prefix) : len(raw) - len(suffix)] if prefix else raw
        variable = _add_candidate(
            candidates,
            identity=f"compose:{relative_path}:{service.name}:environment-list:{index}:{key}",
            base_name=f"{_service_prefix(role_name, service)}_{_normalize_name(key)}",
            value=value,
            is_secret=is_secret,
        )
        edits.append(
            _Edit(
                value_start,
                value_end,
                (variable,) if not prefix else (prefix, variable, suffix),
            )
        )


def _list_environment_value_span(content: str, start: int, end: int, key: str) -> tuple[int, int]:
    item = content[start:end]
    prefix, suffix = _scalar_wrapper(item)
    inner_start = start + len(prefix)
    inner_end = end - len(suffix)
    separator = content.find("=", inner_start, inner_end)
    if separator == -1 or content[inner_start:separator] != key:
        raise GenerationError("remote Compose source has an unsupported environment item")
    return separator + 1, inner_end


def _record_dotenv_environment_decisions(
    source_service: CommentedMap,
    service: Service,
    relative_path: PurePosixPath,
    project_name: str,
    secret_policy: SecretPolicy | None,
    canonical_secret_classifications: dict[tuple[str, str], bool],
    decisions: dict[str, set[bool]],
) -> None:
    environment = source_service.get("environment")
    if isinstance(environment, CommentedMap):
        for key, value in environment.items():
            if isinstance(key, str) and isinstance(value, str):
                _record_dotenv_environment_decision(
                    key,
                    value,
                    _source_environment_secret(
                        service,
                        key,
                        value,
                        _mapping_source_position(environment, key, relative_path),
                        project_name,
                        secret_policy,
                        canonical_secret_classifications,
                    ),
                    decisions,
                )
        return
    if isinstance(environment, CommentedSeq):
        for index, item in enumerate(environment):
            if not isinstance(item, str):
                continue
            key, separator, value = item.partition("=")
            if key and separator:
                _record_dotenv_environment_decision(
                    key,
                    value,
                    _source_environment_secret(
                        service,
                        key,
                        value,
                        _sequence_source_position(environment, index, relative_path),
                        project_name,
                        secret_policy,
                        canonical_secret_classifications,
                    ),
                    decisions,
                )


def _plan_dotenv_edits(
    candidates: dict[str, _Candidate],
    edits: list[_Edit],
    content: str,
    relative_path: PurePosixPath,
    project_name: str,
    role_name: str,
    secret_policy: SecretPolicy | None,
    environment_decisions: dict[str, set[bool]],
) -> None:
    for index, entry in enumerate(_dotenv_entries(content)):
        secret_policy_decision = _dotenv_secret_policy_decision(
            secret_policy, project_name, relative_path, entry.key
        )
        if secret_policy_decision is not None:
            is_secret = secret_policy_decision == "secret"
        else:
            decisions = environment_decisions.get(entry.key, set())
            if decisions:
                is_secret = True in decisions
            else:
                classification = classify_environment(
                    project_name,
                    f"dotenv:{relative_path}",
                    entry.key,
                    entry.semantic_value,
                    SourcePosition(relative_path, entry.line, entry.column),
                )
                is_secret = classification.is_secret
        raw = content[entry.start : entry.end]
        prefix, suffix = _scalar_wrapper(raw)
        value = raw[len(prefix) : len(raw) - len(suffix)] if prefix else raw
        variable = _add_candidate(
            candidates,
            identity=f"dotenv:{relative_path}:{index}:{entry.key}",
            base_name=(
                f"{role_name}_dotenv_{_source_path_name(relative_path)}_"
                f"{_normalize_name(entry.key)}"
            ),
            value=value,
            is_secret=is_secret,
        )
        edits.append(
            _Edit(
                entry.start,
                entry.end,
                (variable,) if not prefix else (prefix, variable, suffix),
            )
        )


def _dotenv_secret_policy_decision(
    secret_policy: SecretPolicy | None, project: str, source: PurePosixPath, key: str
) -> str | None:
    if secret_policy is None:
        return None
    result = secret_policy.dotenv_decision_for(project, source, key)
    if result is not None and result not in {"secret", "plain"}:
        raise GenerationError("dotenv secret policy returned an invalid decision")
    return result


_SIMPLE_INTERPOLATION = re.compile(r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$")


def _record_dotenv_environment_decision(
    key: str,
    value: str,
    is_secret: bool,
    decisions: dict[str, set[bool]],
) -> None:
    match = _SIMPLE_INTERPOLATION.fullmatch(value)
    if match is None:
        return
    dotenv_key = match.group(1) or match.group(2)
    if dotenv_key is not None:
        decisions.setdefault(dotenv_key, set()).add(is_secret)


@dataclass(frozen=True)
class _DotenvEntry:
    """One dotenv assignment whose lexical value can be substituted exactly."""

    key: str
    semantic_value: str
    start: int
    end: int
    line: int
    column: int


_DOTENV_ASSIGNMENT = re.compile(r"[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=")


def _dotenv_entries(content: str) -> tuple[_DotenvEntry, ...]:
    entries: list[_DotenvEntry] = []
    offset = 0
    for line_number, line in enumerate(content.splitlines(keepends=True), start=1):
        body = line.rstrip("\r\n")
        match = _DOTENV_ASSIGNMENT.match(body)
        if match is None:
            offset += len(line)
            continue
        value_start = offset + match.end()
        while value_start < offset + len(body) and content[value_start] in " \t":
            value_start += 1
        value_end = _dotenv_value_end(content, value_start, offset + len(body))
        lexical_value = content[value_start:value_end]
        entries.append(
            _DotenvEntry(
                key=match.group(1),
                semantic_value=_dotenv_semantic_value(lexical_value),
                start=value_start,
                end=value_end,
                line=line_number,
                column=value_start - offset + 1,
            )
        )
        offset += len(line)
    return tuple(entries)


def _dotenv_value_end(content: str, start: int, line_end: int) -> int:
    if start == line_end:
        return start
    if content[start] in {"'", '"'}:
        return _quoted_scalar_end(content, start)
    fragment = content[start:line_end]
    comment = re.search(r"\s+#", fragment)
    end = start + (comment.start() if comment is not None else len(fragment))
    while end > start and content[end - 1] in " \t":
        end -= 1
    return end


def _dotenv_semantic_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _image_parts(service: Service) -> tuple[str, str, str]:
    image = service.image
    if image.repository is None or image.reference is None or image.separator is None:
        raise GenerationError("remote Compose model has an invalid image")
    return image.repository, image.reference, image.separator


def _long_port(source_port: CommentedMap) -> tuple[str, str] | None:
    published = source_port.get("published")
    target = source_port.get("target")
    if isinstance(published, bool) or not isinstance(published, (str, int)):
        return None
    if isinstance(target, bool) or not isinstance(target, (str, int)):
        return None
    return str(published), str(target)


def _short_port(value: str) -> tuple[str, str] | None:
    before, separator, target_with_protocol = value.rpartition(":")
    if not separator or not before or not target_with_protocol:
        return None
    target = target_with_protocol.split("/", maxsplit=1)[0]
    published = before.rpartition(":")[2] or before
    if not published or not target:
        return None
    return published, target


def _short_port_published_span(
    content: str, start: int, end: int, published: str
) -> tuple[int, int]:
    prefix, suffix = _scalar_wrapper(content[start:end])
    inner_start = start + len(prefix)
    inner_end = end - len(suffix)
    inner = content[inner_start:inner_end]
    for match in re.finditer(re.escape(published), inner):
        before = inner[: match.start()]
        after = inner[match.end() :]
        if (not before or before.endswith(":")) and (
            after.startswith(":") or after.startswith("/")
        ):
            return inner_start + match.start(), inner_start + match.end()
    raise GenerationError("remote Compose source has an unsupported port")


def _matching_port(
    ports: tuple[Port, ...], published: str, target: str, used: set[int]
) -> int | None:
    for index, port in enumerate(ports):
        if index not in used and (port.published, port.target) == (published, target):
            return index
    return None


def _add_candidate(
    candidates: dict[str, _Candidate],
    *,
    identity: str,
    base_name: str,
    value: str,
    is_secret: bool,
) -> _Candidate:
    candidate = _Candidate(identity, base_name, value, is_secret)
    previous = candidates.setdefault(identity, candidate)
    if previous != candidate:
        raise GenerationError("remote source parameterization is ambiguous")
    return previous


def _variable_names(candidates: Iterable[_Candidate], reserved_names: set[str]) -> dict[str, str]:
    values = tuple(candidates)
    by_base: dict[str, list[_Candidate]] = {}
    for candidate in values:
        by_base.setdefault(candidate.base_name, []).append(candidate)
    names: dict[str, str] = {}
    for base_name, group in by_base.items():
        if len(group) == 1 and base_name not in reserved_names:
            names[group[0].identity] = base_name
            continue
        for candidate in group:
            digest = hashlib.sha256(candidate.identity.encode("utf-8")).hexdigest()[:8]
            names[candidate.identity] = f"{base_name}_{digest}"
    return names


def _value_span(content: str, mapping: CommentedMap, key: str) -> tuple[int, int]:
    if not _has_direct_source_value(mapping, key):
        raise GenerationError("remote Compose source has an unsupported scalar")
    position = mapping.lc.value(key)
    if position is None:
        raise GenerationError("remote Compose source has an unsupported scalar")
    return _scalar_span(content, _offset_for_position(content, position))


def _has_direct_source_value(mapping: CommentedMap, key: str) -> bool:
    """Return whether a mapping owns a source span for the named value.

    ruamel resolves merge keys and aliases when reading mappings, but its locations for inherited
    or aliased values point at the defining anchor (or are absent).  Those locations are not safe
    to edit for the consuming service.
    """
    if not any(item_key == key for item_key, _ in mapping.non_merged_items()):
        return False
    key_position = mapping.lc.key(key)
    value_position = mapping.lc.value(key)
    return (
        key_position is not None
        and value_position is not None
        and value_position >= key_position
    )


def _item_span(content: str, sequence: CommentedSeq, index: int) -> tuple[int, int]:
    position = sequence.lc.item(index)
    if position is None:
        raise GenerationError("remote Compose source has an unsupported scalar")
    return _scalar_span(content, _offset_for_position(content, position))


def _offset_for_position(content: str, position: tuple[int, int]) -> int:
    line, column = position
    offsets = [0]
    offsets.extend(index + 1 for index, character in enumerate(content) if character == "\n")
    try:
        return offsets[line] + column
    except IndexError as error:
        raise GenerationError("remote Compose source has invalid scalar locations") from error


def _scalar_span(content: str, start: int) -> tuple[int, int]:
    if start >= len(content) or content[start] in "|>&*!":
        raise GenerationError("remote Compose source has an unsupported scalar")
    if content[start] in {"'", '"'}:
        return start, _quoted_scalar_end(content, start)
    line_end = content.find("\n", start)
    if line_end == -1:
        line_end = len(content)
    if line_end > start and content[line_end - 1] == "\r":
        line_end -= 1
    fragment = content[start:line_end]
    comment = re.search(r"\s+#", fragment)
    value_end = start + (comment.start() if comment is not None else len(fragment))
    while value_end > start and content[value_end - 1].isspace():
        value_end -= 1
    if value_end == start:
        raise GenerationError("remote Compose source has an unsupported scalar")
    return start, value_end


def _quoted_scalar_end(content: str, start: int) -> int:
    quote = content[start]
    index = start + 1
    while index < len(content):
        if content[index] != quote:
            index += 1
            continue
        if quote == '"' and _is_escaped_double_quote(content, start, index):
            index += 1
            continue
        if quote == "'" and index + 1 < len(content) and content[index + 1] == quote:
            index += 2
            continue
        return index + 1
    raise GenerationError("remote Compose source has an unterminated scalar")


def _is_escaped_double_quote(content: str, start: int, index: int) -> bool:
    backslash_count = 0
    cursor = index - 1
    while cursor > start and content[cursor] == "\\":
        backslash_count += 1
        cursor -= 1
    return backslash_count % 2 == 1


def _scalar_wrapper(value: str) -> tuple[str, str]:
    if value.startswith(("'", '"')):
        return value[0], value[-1]
    return "", ""


def _uses_interpolation(value: str) -> bool:
    """Return whether Compose would treat part of this value as interpolation.

    A dollar sign followed by neither a name nor an opening brace is literal, and ``$$``
    escapes a literal dollar.  Such values can be parameterized safely; active expressions
    must stay verbatim so Compose resolves them at deployment time.
    """
    index = 0
    while index < len(value):
        if value[index] != "$":
            index += 1
            continue
        if index + 1 == len(value):
            return False
        following = value[index + 1]
        if following == "$":
            index += 2
            continue
        if following == "{" or following == "_" or (
            following.isascii() and following.isalpha()
        ):
            return True
        index += 1
    return False


def _apply_edits(
    content: str, edits: list[_Edit], names: dict[str, str], role_name: str
) -> str:
    result: list[str] = []
    offset = 0
    for edit in sorted(edits, key=lambda value: value.start):
        if edit.start < offset or edit.end < edit.start:
            raise GenerationError("remote source parameterization overlaps")
        result.append(_escape_jinja(content[offset : edit.start]))
        for part in edit.parts:
            if isinstance(part, _Candidate):
                variable_name = names[part.identity]
                if part.is_secret:
                    result.append(f"{{{{ {role_name}_secrets['{variable_name}'] }}}}")
                else:
                    result.append(f"{{{{ {variable_name} }}}}")
            else:
                result.append(part)
        offset = edit.end
    result.append(_escape_jinja(content[offset:]))
    return "".join(result)


def _escape_jinja(value: str) -> str:
    substitutions = {"{{": "{{ '{{' }}", "{%": "{{ '{%' }}", "{#": "{{ '{#' }}"}
    return re.sub(r"\{\{|\{%|\{#", lambda match: substitutions[match.group()], value)


def _newline_sequence(content: str) -> str:
    without_crlf = content.replace("\r\n", "")
    has_crlf = "\r\n" in content
    if has_crlf and "\n" in without_crlf:
        raise GenerationError("remote Compose source has mixed line endings")
    return "\r\n" if has_crlf else "\n"


def _service_prefix(role_name: str, service: Service) -> str:
    return f"{role_name}_{_normalize_name(service.name)}"


def _published_port_variable(prefix: str, index: int, count: int) -> str:
    if count == 1:
        return f"{prefix}_published_port"
    return f"{prefix}_published_port_{index}"


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", value).lower()


def _source_path_name(path: PurePosixPath) -> str:
    return _normalize_name(str(path)).strip("_") or "source"
