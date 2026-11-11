"""Validate and apply SOPS configuration for remote generation."""

from __future__ import annotations

import json
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from subprocess import TimeoutExpired, run

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from compose2role.errors import GenerationError

SOPS_TARGET = PurePosixPath("vars/secrets.sops.yml")


@dataclass(frozen=True)
class SopsConfiguration:
    """A validated operator-owned SOPS config and executable."""

    path: Path
    executable: str


def validate_sops_config(path: Path) -> None:
    """Validate operator-owned SOPS coverage without copying or encrypting anything."""
    if not path.is_file():
        raise GenerationError("SOPS config could not be read")
    _validate_creation_rule(path)


def resolve_sops_configuration(explicit_path: Path | None) -> SopsConfiguration:
    """Validate the selected SOPS configuration before remote acquisition."""
    selected_path = explicit_path
    if selected_path is None:
        environment_path = os.environ.get("COMPOSE2ROLE_SOPS_CONFIG")
        selected_path = Path(environment_path) if environment_path else None
    if selected_path is None or not selected_path.is_file():
        raise GenerationError(
            "remote generation requires an existing SOPS config via --sops-config "
            "or COMPOSE2ROLE_SOPS_CONFIG"
        )

    executable = shutil.which("sops")
    if executable is None:
        raise GenerationError("remote generation requires the SOPS executable")
    _validate_creation_rule(selected_path)
    return SopsConfiguration(path=selected_path, executable=executable)


def encrypt_secret_values(configuration: SopsConfiguration, values: Mapping[str, str]) -> bytes:
    """Encrypt an in-memory secret mapping without creating a plaintext file."""
    plaintext = json.dumps(dict(values), sort_keys=True).encode("utf-8")
    try:
        result = run(
            (
                configuration.executable,
                "--config",
                str(configuration.path),
                "--encrypt",
                "--input-type",
                "yaml",
                "--output-type",
                "yaml",
                "--filename-override",
                str(SOPS_TARGET),
                "/dev/stdin",
            ),
            check=False,
            capture_output=True,
            input=plaintext,
            timeout=30,
        )
    except (FileNotFoundError, TimeoutExpired, OSError) as error:
        raise GenerationError("SOPS encryption failed") from error
    if result.returncode != 0 or not result.stdout:
        raise GenerationError("SOPS encryption failed")
    _validate_encrypted_output(values, result.stdout)
    return result.stdout


def _validate_encrypted_output(values: Mapping[str, str], output: bytes) -> None:
    try:
        document: object = YAML(typ="safe").load(output.decode("utf-8"))
    except (UnicodeDecodeError, YAMLError) as error:
        raise GenerationError("SOPS encryption output is invalid") from error
    if not isinstance(document, dict):
        raise GenerationError("SOPS encryption output is invalid")
    plaintext_values = {value for value in values.values() if value}
    for key, plaintext in values.items():
        encrypted_value = document.get(key)
        if plaintext == "":
            # SOPS deliberately leaves empty strings unencrypted; there is nothing to protect.
            if encrypted_value != "":
                raise GenerationError("SOPS encryption output is invalid")
            continue
        if not (
            isinstance(encrypted_value, str)
            and encrypted_value.startswith("ENC[")
            and encrypted_value.endswith("]")
        ):
            raise GenerationError("SOPS encryption output is invalid")
    for key, value in document.items():
        if key != "sops" and isinstance(value, str) and value in plaintext_values:
            raise GenerationError("SOPS encryption output is invalid")


def _validate_creation_rule(path: Path) -> None:
    try:
        document: object = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    except (OSError, YAMLError, UnicodeDecodeError) as error:
        raise GenerationError("SOPS config could not be read") from error
    if not isinstance(document, dict):
        raise GenerationError("SOPS config must define creation rules")
    rules = document.get("creation_rules")
    if not isinstance(rules, list):
        raise GenerationError("SOPS config must define creation rules")

    target = str(SOPS_TARGET)
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        path_regex = rule.get("path_regex")
        if path_regex is None:
            return
        if not isinstance(path_regex, str):
            continue
        try:
            if re.search(path_regex, target) is not None:
                return
        except re.error as error:
            raise GenerationError("SOPS config contains an invalid path_regex") from error
    raise GenerationError("SOPS config has no creation rule for vars/secrets.sops.yml")
