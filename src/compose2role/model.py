"""The typed Compose model used by remote audit."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath

from compose2role.errors import ComposeParseError


@dataclass(frozen=True)
class SourcePosition:
    """A one-based location in a source compose file."""

    path: PurePosixPath
    line: int
    column: int

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column}"


@dataclass(frozen=True)
class Image:
    """An image repository and its tag or digest."""

    source: str
    repository: str | None
    reference: str | None
    separator: str | None

    @property
    def uses_interpolation(self) -> bool:
        """Whether Compose must resolve the image expression itself."""
        return "${" in self.source

    @property
    def is_pinned(self) -> bool:
        """Whether the image has a tag other than ``latest`` or a digest."""
        if self.uses_interpolation:
            return True
        return self.separator == "@" or self.reference != "latest"


@dataclass(frozen=True)
class Port:
    """A resolved port mapping."""

    target: str
    published: str | None
    location: SourcePosition


@dataclass(frozen=True)
class EnvironmentVariable:
    """An inline, mapping-form environment variable from a Compose service."""

    name: str
    value: str
    is_secret: bool
    location: SourcePosition


@dataclass(frozen=True)
class Service:
    """A Compose service."""

    name: str
    image: Image
    ports: tuple[Port, ...]
    environment: tuple[EnvironmentVariable, ...]
    is_privileged: bool
    uses_host_network: bool
    runs_as_root: bool
    has_healthcheck: bool
    has_restart_policy: bool
    option_names: frozenset[str]
    location: SourcePosition


@dataclass(frozen=True)
class Stack:
    """A complete Compose project."""

    services: tuple[Service, ...]
    option_names: frozenset[str]
    name: str | None = None


def parse_canonical_stack(document: object, *, source_path: PurePosixPath) -> Stack:
    """Parse Docker Compose's canonical JSON model for remote audit.

    Canonical JSON has no useful source positions, so every derived value uses the supplied
    synthetic source position. Remote secret classification is intentionally performed separately
    from this parser.
    """
    document_mapping = _canonical_mapping(document, "remote Docker Compose returned invalid JSON")
    services_value = document_mapping.get("services")
    services_mapping = _canonical_mapping(
        services_value, "remote Docker Compose returned no services"
    )
    if not services_mapping:
        raise ComposeParseError("remote Docker Compose returned no services")

    services = tuple(
        _parse_canonical_service(source_path, service_name, service_value)
        for service_name, service_value in services_mapping.items()
    )
    name_value = document_mapping.get("name")
    if name_value is not None and not isinstance(name_value, str):
        raise ComposeParseError("remote Docker Compose returned an invalid project name")
    return Stack(
        services=services,
        option_names=frozenset(document_mapping),
        name=name_value,
    )


def _canonical_mapping(value: object, message: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ComposeParseError(message)
    mapping: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ComposeParseError(message)
        mapping[key] = item
    return mapping


def _parse_canonical_service(
    source_path: PurePosixPath, service_name: str, service_value: object
) -> Service:
    service = _canonical_mapping(service_value, "remote Docker Compose returned an invalid service")
    position = SourcePosition(path=source_path, line=1, column=1)
    image_value = service.get("image")
    if not isinstance(image_value, str) or not image_value:
        raise ComposeParseError("remote Docker Compose returned a service without an image")

    ports_value = service.get("ports", [])
    if not isinstance(ports_value, list):
        raise ComposeParseError("remote Docker Compose returned invalid service ports")
    environment_value = _canonical_mapping(
        service.get("environment", {}), "remote Docker Compose returned invalid service environment"
    )
    environment: list[EnvironmentVariable] = []
    for name, value in environment_value.items():
        if not name or not isinstance(value, str) or _has_unresolved_interpolation(value):
            raise ComposeParseError("remote Docker Compose returned unresolved environment values")
        environment.append(
            EnvironmentVariable(
                name=name,
                value=value,
                is_secret=False,
                location=position,
            )
        )

    return Service(
        name=service_name,
        image=_parse_canonical_image(image_value),
        ports=tuple(_parse_canonical_port(value, position) for value in ports_value),
        environment=tuple(environment),
        is_privileged=service.get("privileged") is True,
        uses_host_network=service.get("network_mode") == "host",
        runs_as_root=_runs_as_root(service.get("user")),
        has_healthcheck=_has_healthcheck(service),
        has_restart_policy=_has_restart_policy(service.get("restart")),
        option_names=frozenset(service),
        location=position,
    )


def _parse_canonical_image(image: str) -> Image:
    if _has_unresolved_interpolation(image):
        raise ComposeParseError("remote Docker Compose returned an unresolved image reference")
    if "@" in image:
        repository, reference = image.split("@", maxsplit=1)
        if repository and reference:
            return Image(source=image, repository=repository, reference=reference, separator="@")
        raise ComposeParseError("remote Docker Compose returned an invalid image reference")

    last_slash = image.rfind("/")
    last_colon = image.rfind(":")
    if last_colon > last_slash:
        repository, reference = image.rsplit(":", maxsplit=1)
        if repository and reference:
            return Image(source=image, repository=repository, reference=reference, separator=":")
        raise ComposeParseError("remote Docker Compose returned an invalid image reference")
    return Image(source=image, repository=image, reference="latest", separator=":")


def _has_unresolved_interpolation(value: str) -> bool:
    """Return whether a canonical value still contains an active Compose interpolation."""
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


def _parse_canonical_port(value: object, position: SourcePosition) -> Port:
    port = _canonical_mapping(value, "remote Docker Compose returned an invalid port mapping")
    target = port.get("target")
    published = port.get("published")
    if isinstance(target, bool) or not isinstance(target, (int, str)):
        raise ComposeParseError("remote Docker Compose returned an invalid port mapping")
    if isinstance(published, bool) or not isinstance(published, (int, str, type(None))):
        raise ComposeParseError("remote Docker Compose returned an invalid port mapping")
    return Port(
        target=str(target),
        published=None if published is None else str(published),
        location=position,
    )


def _runs_as_root(user: object) -> bool:
    return user is None or user == "" or user == "0" or user == 0


def _has_healthcheck(service: Mapping[str, object]) -> bool:
    if "healthcheck" not in service:
        return False

    healthcheck: object = service.get("healthcheck")
    if not isinstance(healthcheck, Mapping):
        return True
    if healthcheck.get("disable") is True:
        return False
    test: object = healthcheck.get("test")
    return test != "NONE"


def _has_restart_policy(restart: object) -> bool:
    return isinstance(restart, str) and restart not in {"", "no"}
