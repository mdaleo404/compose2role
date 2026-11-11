"""Value-aware secret classification that never exposes effective values."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from compose2role.model import SourcePosition
    from compose2role.secret_policy import SecretPolicy

_SECRET_COMPONENTS = frozenset(
    {
        "CREDENTIAL",
        "CREDENTIALS",
        "DSN",
        "PASS",
        "PASSWORD",
        "SECRET",
        "TOKEN",
    }
)
_CREDENTIAL_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@")
_JWT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_OPAQUE_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,}$")
_OPAQUE_TOKEN_PREFIXES = ("sk-", "ghp_", "xoxb-")


@dataclass(frozen=True)
class EnvironmentClassification:
    """A value-free secret decision for an effective service environment entry."""

    service: str
    key: str
    is_secret: bool
    reason: str
    location: SourcePosition

    def as_json(self) -> dict[str, str]:
        """Return the classification report without the effective value."""
        return {
            "key": self.key,
            "location": str(self.location),
            "reason": self.reason,
            "service": self.service,
        }


def is_secret_key(key: str) -> bool:
    """Return whether an environment-variable name likely carries a secret.

    ``KEY_PREFIX`` deliberately does not match: matching arbitrary ``KEY`` substrings
    creates too many false positives. A standalone ``KEY`` or a ``*_KEY`` suffix does
    match; later configuration can allow-list public keys explicitly.
    """
    normalized = key.upper()
    components = frozenset(normalized.split("_"))
    return (
        bool(components & _SECRET_COMPONENTS)
        or normalized == "KEY"
        or normalized.endswith("_KEY")
    )


def classify_environment(
    project: str,
    service: str,
    key: str,
    value: str,
    location: SourcePosition,
    secret_policy: SecretPolicy | None = None,
) -> EnvironmentClassification:
    """Classify an effective environment value without including it in the result."""
    secret_policy_decision = (
        secret_policy.decision_for(project, service, key)
        if secret_policy is not None
        else None
    )
    if secret_policy_decision is not None:
        return EnvironmentClassification(
            service=service,
            key=key,
            is_secret=secret_policy_decision == "secret",
            reason=f"secret-policy:forced-{secret_policy_decision}",
            location=location,
        )
    if is_secret_key(key):
        return EnvironmentClassification(
            service=service,
            key=key,
            is_secret=True,
            reason="key-name",
            location=location,
        )
    if _CREDENTIAL_URI.match(value):
        return EnvironmentClassification(
            service=service,
            key=key,
            is_secret=True,
            reason="value:credential-uri",
            location=location,
        )
    if "-----BEGIN" in value and "PRIVATE KEY-----" in value:
        return EnvironmentClassification(
            service=service,
            key=key,
            is_secret=True,
            reason="value:private-key",
            location=location,
        )
    if _JWT.match(value):
        return EnvironmentClassification(
            service=service,
            key=key,
            is_secret=True,
            reason="value:jwt",
            location=location,
        )
    if value.startswith(_OPAQUE_TOKEN_PREFIXES) or _is_mixed_opaque_token(value):
        return EnvironmentClassification(
            service=service,
            key=key,
            is_secret=True,
            reason="value:opaque-token",
            location=location,
        )
    return EnvironmentClassification(
        service=service,
        key=key,
        is_secret=False,
        reason="not-secret",
        location=location,
    )


def _is_mixed_opaque_token(value: str) -> bool:
    return bool(
        _OPAQUE_TOKEN.match(value)
        and any(character.islower() for character in value)
        and any(character.isupper() for character in value)
        and any(character.isdigit() for character in value)
    )
