from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from compose2role.errors import SecretPolicyError
from compose2role.secret_policy import load_secret_policy


def _write_policy(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "secret-policy.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_secret_policy_key_list_expands_to_one_exact_rule_per_key(tmp_path: Path) -> None:
    policy = load_secret_policy(
        _write_policy(
            tmp_path,
            """\
[[rules]]
project = "myapp"
service = "web"
key = ["API_TOKEN", "DB_PASSWORD"]
decision = "plain"
""",
        )
    )

    assert policy.decision_for("myapp", "web", "API_TOKEN") == "plain"
    assert policy.decision_for("myapp", "web", "DB_PASSWORD") == "plain"
    assert policy.decision_for("myapp", "web", "OTHER_KEY") is None
    assert policy.decision_for("myapp", "worker", "API_TOKEN") is None


def test_secret_policy_dotenv_key_list_expands_to_one_exact_rule_per_key(tmp_path: Path) -> None:
    policy = load_secret_policy(
        _write_policy(
            tmp_path,
            """\
[[dotenv_rules]]
project = "myapp"
source = ".env"
key = ["MAIL_PASSWORD", "SMTP_TOKEN"]
decision = "secret"
""",
        )
    )

    assert policy.dotenv_decision_for("myapp", PurePosixPath(".env"), "MAIL_PASSWORD") == "secret"
    assert policy.dotenv_decision_for("myapp", PurePosixPath(".env"), "SMTP_TOKEN") == "secret"
    assert policy.dotenv_decision_for("myapp", PurePosixPath(".env"), "OTHER_KEY") is None
    assert policy.dotenv_decision_for("myapp", PurePosixPath(".env.local"), "SMTP_TOKEN") is None


def test_secret_policy_single_key_rule_still_matches_exactly(tmp_path: Path) -> None:
    policy = load_secret_policy(
        _write_policy(
            tmp_path,
            """\
[[rules]]
project = "myapp"
service = "web"
key = "API_TOKEN"
decision = "secret"
""",
        )
    )

    assert policy.decision_for("myapp", "web", "API_TOKEN") == "secret"
    assert policy.decision_for("myapp", "web", "API_TOKEN_2") is None


@pytest.mark.parametrize(
    "key_value",
    ['[]', '["API_TOKEN", 7]', '["API_TOKEN", ""]', '""', "7"],
)
def test_secret_policy_rejects_invalid_environment_key_values(
    tmp_path: Path, key_value: str
) -> None:
    policy_path = _write_policy(
        tmp_path,
        f"""\
[[rules]]
project = "myapp"
service = "web"
key = {key_value}
decision = "secret"
""",
    )

    with pytest.raises(SecretPolicyError, match="keys must be non-empty strings"):
        load_secret_policy(policy_path)


@pytest.mark.parametrize(
    "key_value",
    ['[]', '["MAIL_PASSWORD", 7]', '["MAIL_PASSWORD", ""]', '""', "7"],
)
def test_secret_policy_rejects_invalid_dotenv_key_values(tmp_path: Path, key_value: str) -> None:
    policy_path = _write_policy(
        tmp_path,
        f"""\
[[dotenv_rules]]
project = "myapp"
source = ".env"
key = {key_value}
decision = "secret"
""",
    )

    with pytest.raises(SecretPolicyError, match="keys must be non-empty strings"):
        load_secret_policy(policy_path)


def test_secret_policy_rejects_conflicts_between_list_and_single_rules(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path,
        """\
[[rules]]
project = "myapp"
service = "web"
key = ["API_TOKEN", "LOG_LEVEL"]
decision = "secret"

[[rules]]
project = "myapp"
service = "web"
key = "LOG_LEVEL"
decision = "plain"
""",
    )

    with pytest.raises(SecretPolicyError, match="conflicting exact rules"):
        load_secret_policy(policy_path)
