"""Controller-side secret policy overrides for remote environment secret classification."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from compose2role.errors import SecretPolicyError

_ENVIRONMENT_RULE_KEYS = frozenset({"project", "service", "key", "decision"})
_DOTENV_RULE_KEYS = frozenset({"project", "source", "key", "decision"})


@dataclass(frozen=True)
class SecretRule:
    """One exact environment classification override with no value data."""

    project: str
    service: str
    key: str
    decision: str


@dataclass(frozen=True)
class DotenvSecretRule:
    """One exact, value-free override for a copied dotenv entry."""

    project: str
    source: PurePosixPath
    key: str
    decision: str


@dataclass(frozen=True)
class SecretPolicy:
    """Exact controller-side secret policy rules."""

    rules: tuple[SecretRule, ...]
    dotenv_rules: tuple[DotenvSecretRule, ...] = ()

    def decision_for(self, project: str, service: str, key: str) -> str | None:
        """Return the exact matching decision, if the secret policy has one."""
        for rule in self.rules:
            if (rule.project, rule.service, rule.key) == (project, service, key):
                return rule.decision
        return None

    def dotenv_decision_for(
        self, project: str, source: PurePosixPath, key: str
    ) -> str | None:
        """Return the exact matching copied-dotenv decision, if present."""
        for rule in self.dotenv_rules:
            if (rule.project, rule.source, rule.key) == (project, source, key):
                return rule.decision
        return None


def load_secret_policy(path: Path) -> SecretPolicy:
    """Load a secret policy without retaining arbitrary policy values in its interface."""
    try:
        document: object = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise SecretPolicyError("secret policy could not be read") from error
    if not isinstance(document, dict):
        raise SecretPolicyError("secret policy is invalid")

    if frozenset(document) - {"rules", "dotenv_rules"}:
        raise SecretPolicyError("secret policy must define only exact rule tables")
    rules_value: object = document.get("rules", [])
    dotenv_rules_value: object = document.get("dotenv_rules", [])
    if not isinstance(rules_value, list) or not isinstance(dotenv_rules_value, list):
        raise SecretPolicyError("secret policy must define rules")
    if not rules_value and not dotenv_rules_value:
        raise SecretPolicyError("secret policy must define rules")

    rules: list[SecretRule] = []
    decisions: dict[tuple[str, str, str], str] = {}
    for rule_value in rules_value:
        for rule in _parse_rule(rule_value):
            identity = (rule.project, rule.service, rule.key)
            previous_decision = decisions.get(identity)
            if previous_decision is not None and previous_decision != rule.decision:
                raise SecretPolicyError("secret policy has conflicting exact rules")
            decisions[identity] = rule.decision
            rules.append(rule)
    dotenv_rules: list[DotenvSecretRule] = []
    dotenv_decisions: dict[tuple[str, PurePosixPath, str], str] = {}
    for rule_value in dotenv_rules_value:
        for dotenv_rule in _parse_dotenv_rule(rule_value):
            dotenv_identity = (dotenv_rule.project, dotenv_rule.source, dotenv_rule.key)
            previous_decision = dotenv_decisions.get(dotenv_identity)
            if previous_decision is not None and previous_decision != dotenv_rule.decision:
                raise SecretPolicyError("secret policy has conflicting exact rules")
            dotenv_decisions[dotenv_identity] = dotenv_rule.decision
            dotenv_rules.append(dotenv_rule)
    return SecretPolicy(rules=tuple(rules), dotenv_rules=tuple(dotenv_rules))


def _rule_keys(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        if not value:
            raise SecretPolicyError("secret policy rule keys must be non-empty strings")
        return (value,)
    if isinstance(value, list) and value:
        keys: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item:
                raise SecretPolicyError("secret policy rule keys must be non-empty strings")
            keys.append(item)
        return tuple(keys)
    raise SecretPolicyError("secret policy rule keys must be non-empty strings")


def _parse_rule(value: object) -> list[SecretRule]:
    if not isinstance(value, dict):
        raise SecretPolicyError("secret policy is invalid")
    rule: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise SecretPolicyError("secret policy is invalid")
        rule[key] = item
    if frozenset(rule) != _ENVIRONMENT_RULE_KEYS:
        raise SecretPolicyError("secret policy rules must contain only exact match fields")

    project = rule["project"]
    service = rule["service"]
    key = rule["key"]
    decision = rule["decision"]
    if (
        not isinstance(project, str)
        or not project
        or not isinstance(service, str)
        or not service
        or not isinstance(decision, str)
        or decision not in {"secret", "plain"}
    ):
        raise SecretPolicyError("secret policy rules are invalid")
    return [
        SecretRule(project=project, service=service, key=item, decision=decision)
        for item in _rule_keys(key)
    ]


def _parse_dotenv_rule(value: object) -> list[DotenvSecretRule]:
    if not isinstance(value, dict):
        raise SecretPolicyError("secret policy is invalid")
    rule: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise SecretPolicyError("secret policy is invalid")
        rule[key] = item
    if frozenset(rule) != _DOTENV_RULE_KEYS:
        raise SecretPolicyError("dotenv secret policy rules must contain only exact match fields")

    project = rule["project"]
    source_value = rule["source"]
    key = rule["key"]
    decision = rule["decision"]
    if (
        not isinstance(project, str)
        or not project
        or not isinstance(source_value, str)
        or not source_value
        or not isinstance(decision, str)
        or decision not in {"secret", "plain"}
    ):
        raise SecretPolicyError("dotenv secret policy rules are invalid")
    source = PurePosixPath(source_value)
    if source.is_absolute() or ".." in source.parts or str(source) != source_value:
        raise SecretPolicyError("dotenv secret policy source paths must be root-relative")
    return [
        DotenvSecretRule(project=project, source=source, key=item, decision=decision)
        for item in _rule_keys(key)
    ]
