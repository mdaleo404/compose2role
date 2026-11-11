"""Audit findings derived from the typed Compose model."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from compose2role.model import SourcePosition, Stack


class Severity(StrEnum):
    """The impact level assigned to a finding."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """One stable, machine-readable diagnostic for a compose project."""

    id: str
    severity: Severity
    message: str
    location: SourcePosition
    service: str | None = None

    def as_json(self) -> dict[str, str | None]:
        """Return the stable JSON representation used by the CLI."""
        return {
            "id": self.id,
            "severity": self.severity.value,
            "message": self.message,
            "location": str(self.location),
            "service": self.service,
        }


def audit_stack(stack: Stack) -> tuple[Finding, ...]:
    """Return all audit findings supported by the current ruleset."""
    findings: list[Finding] = []
    for service in stack.services:
        if not service.image.is_pinned:
            findings.append(
                Finding(
                    id="C2R001",
                    severity=Severity.WARNING,
                    message="image is not pinned to a tag or digest",
                    location=service.location,
                    service=service.name,
                )
            )
        for environment in service.environment:
            if environment.is_secret:
                findings.append(
                    Finding(
                        id="C2R002",
                        severity=Severity.ERROR,
                        message=(
                            f"{environment.name} is an inline secret-shaped environment variable; "
                            "move it to SOPS"
                        ),
                        location=environment.location,
                        service=service.name,
                    )
                )
        if service.is_privileged:
            findings.append(
                Finding(
                    id="C2R009",
                    severity=Severity.WARNING,
                    message="service enables privileged mode",
                    location=service.location,
                    service=service.name,
                )
            )
        if service.uses_host_network:
            findings.append(
                Finding(
                    id="C2R010",
                    severity=Severity.WARNING,
                    message="service uses host networking",
                    location=service.location,
                    service=service.name,
                )
            )
        if service.runs_as_root:
            findings.append(
                Finding(
                    id="C2R011",
                    severity=Severity.WARNING,
                    message="service runs as root",
                    location=service.location,
                    service=service.name,
                )
            )
        if not service.has_healthcheck:
            findings.append(
                Finding(
                    id="C2R012",
                    severity=Severity.INFO,
                    message="service has no healthcheck",
                    location=service.location,
                    service=service.name,
                )
            )
        if not service.has_restart_policy:
            findings.append(
                Finding(
                    id="C2R016",
                    severity=Severity.WARNING,
                    message="service has no restart policy",
                    location=service.location,
                    service=service.name,
                )
            )
    return tuple(findings)


def classified_secret_finding(
    service: str, key: str, reason: str, location: SourcePosition
) -> Finding:
    """Report a remote secret classification without exposing its effective value."""
    return Finding(
        id="C2R025",
        severity=Severity.INFO,
        message=f"{key} is classified as a secret ({reason})",
        location=location,
        service=service,
    )
