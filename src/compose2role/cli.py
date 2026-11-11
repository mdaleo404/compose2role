"""The compose2role command-line interface."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from difflib import unified_diff
from pathlib import Path

import click

from compose2role.config import HostProfile, load_repository_config
from compose2role.discover import discover_projects, validate_docker_context
from compose2role.doctor import DoctorCheck, DoctorReport, diagnose, target_for
from compose2role.drift import inspect_drift
from compose2role.emit import external_prerequisites, normalize_remote_role_name
from compose2role.errors import (
    Compose2RoleError,
    ConfigurationError,
    DockerContextError,
    GenerationError,
)
from compose2role.findings import Finding, Severity
from compose2role.layout import AnsibleLayout, discover_layout
from compose2role.remote import resolve_remote_projects
from compose2role.remote_generate import generate_remote_projects
from compose2role.resolve import (
    AuditOutcome,
    AuditResult,
    GeneratedProject,
    GenerationOutcome,
    GenerationResult,
    PlanDiff,
    ProjectDrift,
    ProjectFailure,
    ResolvedProject,
)
from compose2role.secret_policy import SecretPolicy, load_secret_policy


class _Command(click.Command):
    """Click command that lists its full short help instead of an ellipsis."""

    def get_short_help_str(self, limit: int = 45) -> str:
        help_text = self.help or ""
        paragraph_end = help_text.find("\n\n")
        if paragraph_end != -1:
            help_text = help_text[:paragraph_end]
        return " ".join(help_text.split())


class _Group(click.Group):
    """Click group that renders every command description without truncation."""

    command_class = _Command


@click.group(cls=_Group, context_settings={"max_content_width": 100})
@click.version_option(package_name="compose2role", message="%(prog)s %(version)s")
def main() -> None:
    """Generate Ansible roles that reproduce remote Docker Compose projects.

    Captures a project over SSH and writes a role that restores its exact Compose files,
    dotenv inputs, and file-backed secrets, then applies them with docker compose. Remote-only:
    generate and audit require --host plus exactly one of --project or --all.
    """


def _color_enabled() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


class _ConfigurationClickError(click.ClickException):
    """Report configuration and layout failures as usage errors."""

    exit_code = 2


def _layout(
    config_path: Path | None,
    *,
    explicit_output: Path | None = None,
    explicit_sops_config: Path | None = None,
    explicit_secret_policy: Path | None = None,
    host: str | None = None,
) -> AnsibleLayout:
    config = load_repository_config(config_path, start=Path.cwd())
    return discover_layout(
        config,
        start=Path.cwd(),
        explicit_output=explicit_output,
        explicit_sops_config=explicit_sops_config,
        explicit_secret_policy=explicit_secret_policy,
        host=host,
    )


def _configured_sudo(explicit: bool | None, profile: HostProfile) -> bool:
    if explicit is not None:
        return explicit
    return bool(profile.sudo)


def _docker_context(explicit: str | None, profile: HostProfile) -> str | None:
    selected = explicit if explicit is not None else profile.docker_context
    if selected is None:
        return None
    try:
        return validate_docker_context(selected)
    except DockerContextError as error:
        raise _ConfigurationClickError(str(error)) from error


def _status(ok: bool, message: str) -> None:
    glyph = "✓" if ok else "✗"
    click.secho(f"{glyph} {message}", fg="green" if ok else "red", color=_color_enabled())


def _visible_findings(findings: tuple[Finding, ...], verbose: bool) -> tuple[Finding, ...]:
    if verbose:
        return findings
    return tuple(finding for finding in findings if finding.severity == Severity.ERROR)


def _echo_findings(findings: tuple[Finding, ...], verbose: bool, *, indent: str = "") -> None:
    for finding in _visible_findings(findings, verbose):
        click.echo(
            f"{indent}{finding.location}: {finding.severity.upper()} "
            f"{finding.id}: {finding.message}"
        )


def _echo_summary(ok_count: int, noun: str, failed_count: int) -> None:
    summary = f"{ok_count} {noun}"
    if failed_count:
        summary = f"{summary}, {failed_count} failed"
    click.echo()
    click.echo(summary)


@main.command()
@click.option(
    "--output",
    "output_directory",
    "-o",
    type=click.Path(path_type=Path),
    help="Roles directory to write into (default: resolved from --config or ansible.cfg).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    help="Repository configuration file to load.",
)
@click.option(
    "--check",
    "check_only",
    is_flag=True,
    help="List the planned files without writing or encrypting anything.",
)
@click.option(
    "--diff",
    "diff_only",
    is_flag=True,
    help="Show value-free changes; write only together with --force.",
)
@click.option(
    "--force",
    "force",
    is_flag=True,
    help="Replace a differing role after backing it up under .compose2role/backups/.",
)
@click.option(
    "--host",
    help="Remote OpenSSH alias or host:port destination (required).",
)
@click.option(
    "--sudo",
    "use_sudo",
    is_flag=True,
    default=None,
    help="Run remote commands with sudo -n.",
)
@click.option(
    "--docker-context",
    "docker_context",
    help="Remote Docker context to use (default: the remote CLI default).",
)
@click.option(
    "--project",
    "project_name",
    help="Raw Compose project name to generate (exactly one project).",
)
@click.option(
    "--all",
    "all_projects",
    is_flag=True,
    help="Generate every discovered project.",
)
@click.option(
    "--secret-policy",
    "secret_policy_path",
    type=click.Path(path_type=Path),
    help="TOML secret-classification overrides.",
)
@click.option(
    "--sops-config",
    "sops_config_path",
    type=click.Path(path_type=Path),
    help="SOPS creation-rule file for encrypting secrets (or COMPOSE2ROLE_SOPS_CONFIG).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Also show warning and info findings.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(("text", "json")),
    default="text",
    help="Output format (default: text).",
)
def generate(
    output_directory: Path | None,
    config_path: Path | None,
    check_only: bool,
    diff_only: bool,
    force: bool,
    host: str | None,
    use_sudo: bool | None,
    docker_context: str | None,
    project_name: str | None,
    all_projects: bool,
    secret_policy_path: Path | None,
    sops_config_path: Path | None,
    verbose: bool,
    output_format: str,
) -> None:
    """Generate Ansible roles from remote Compose projects.

    Requires --host and exactly one of --project or --all. Every run, including --check, needs an
    existing SOPS configuration and the sops executable. A byte-identical role is left alone; a
    differing or unmanaged role is refused unless --force is given.
    """
    if host is None:
        raise click.UsageError(
            "local generation was removed; use --host with exactly one of --project or --all"
        )
    if check_only and diff_only:
        raise click.UsageError("--check and --diff are mutually exclusive")
    if project_name is None and not all_projects:
        raise click.UsageError("remote generate requires exactly one of --project or --all")
    if project_name is not None and all_projects:
        raise click.UsageError("remote generate accepts only one of --project or --all")

    text_output = output_format == "text"
    if text_output:
        click.echo(f"Discovering projects on {host}...")
    try:
        layout = _layout(
            config_path,
            explicit_output=output_directory,
            explicit_sops_config=sops_config_path,
            explicit_secret_policy=secret_policy_path,
            host=host,
        )
        secret_policy = _load_secret_policy(layout.secret_policy)
        result = generate_remote_projects(
            host,
            layout.roles_directory,
            project_name=project_name,
            all_projects=all_projects,
            use_sudo=_configured_sudo(use_sudo, layout.host),
            docker_context=_docker_context(docker_context, layout.host),
            secret_policy=secret_policy,
            sops_config_path=layout.sops_config,
            check_only=check_only,
            diff_only=diff_only,
            force=force,
            on_outcome=(
                (lambda outcome: _echo_generation_outcome(outcome, verbose))
                if text_output
                else None
            ),
        )
    except ConfigurationError as error:
        raise _ConfigurationClickError(str(error)) from error
    except Compose2RoleError as error:
        raise click.ClickException(str(error)) from error

    if output_format == "json":
        click.echo(json.dumps(result.as_json()))
    else:
        _echo_generation_summary(result)
    if result.failures:
        raise click.exceptions.Exit(1)


def _echo_plan_diff(diff: PlanDiff) -> None:
    for file_diff in diff.files:
        if file_diff.state == "unchanged":
            continue
        if file_diff.withheld:
            reason = (
                f": {file_diff.withheld_reason}"
                if file_diff.withheld_reason is not None
                else ""
            )
            click.echo(
                f"  {file_diff.path}: {file_diff.change} (content withheld{reason})"
            )
            continue
        old_lines = (file_diff.old_text or "").splitlines()
        new_lines = (file_diff.new_text or "").splitlines()
        from_file = "/dev/null" if file_diff.change == "added" else f"a/{file_diff.path}"
        rendered = list(
            unified_diff(
                old_lines,
                new_lines,
                fromfile=from_file,
                tofile=f"b/{file_diff.path}",
                lineterm="",
            )
        )
        for line in rendered:
            click.echo(f"  {line}")
        if file_diff.change == "changed" and not any(
            line.startswith(("+", "-")) for line in rendered
        ):
            click.echo(f"  {file_diff.path}: changed")


def _echo_generation_outcome(outcome: GenerationOutcome, verbose: bool) -> None:
    if isinstance(outcome, GeneratedProject):
        if outcome.checked:
            action = "checked"
        elif outcome.diff is not None and outcome.diff_only:
            action = "unchanged" if outcome.diff.identical else "diff"
        elif outcome.unchanged:
            action = "unchanged"
        else:
            action = "generated"
        _status(True, f"{outcome.name} -> {outcome.role_name} ({action})")
        _echo_prerequisites(outcome.project)
        _echo_findings(outcome.project.findings, verbose, indent="  ")
        if outcome.diff is not None:
            _echo_plan_diff(outcome.diff)
        if outcome.checked:
            for path in outcome.files:
                click.echo(f"  {path}")
        return
    role = f" -> {outcome.role_name}" if outcome.role_name is not None else ""
    _status(False, f"{outcome.name}{role}: FAILED ({outcome.category}): {outcome.message}")
    _echo_findings(outcome.findings, verbose, indent="  ")


def _echo_prerequisites(project: ResolvedProject) -> None:
    prerequisites = external_prerequisites(project.canonical_document)
    if prerequisites:
        rendered = ", ".join(f"external {kind} {name}" for kind, name in prerequisites)
        click.echo(f"  prerequisites: {rendered}")


def _echo_generation_summary(result: GenerationResult) -> None:
    generated = tuple(
        outcome for outcome in result.outcomes if isinstance(outcome, GeneratedProject)
    )
    if any(outcome.checked for outcome in generated):
        noun = "checked"
    elif generated and all(outcome.diff is not None and outcome.diff_only for outcome in generated):
        noun = "unchanged" if all(outcome.unchanged for outcome in generated) else "diff"
    elif generated and all(outcome.unchanged for outcome in generated):
        noun = "unchanged"
    else:
        noun = "generated"
    _echo_summary(len(generated), noun, len(result.failures))


@main.command()
@click.option(
    "--format",
    "output_format",
    type=click.Choice(("text", "json")),
    default="text",
    help="Output format (default: text).",
)
@click.option(
    "--fail-on",
    type=click.Choice(("error", "warning")),
    help="Exit 3 when a finding at this severity or above exists.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Also show warning and info findings.",
)
@click.option(
    "--host",
    help="Remote OpenSSH alias or host:port destination (required).",
)
@click.option(
    "--sudo",
    "use_sudo",
    is_flag=True,
    default=None,
    help="Run remote commands with sudo -n.",
)
@click.option(
    "--docker-context",
    "docker_context",
    help="Remote Docker context to use (default: the remote CLI default).",
)
@click.option(
    "--project",
    "project_name",
    help="Raw Compose project name to audit (exactly one project).",
)
@click.option(
    "--all",
    "all_projects",
    is_flag=True,
    help="Audit every discovered project.",
)
@click.option(
    "--secret-policy",
    "secret_policy_path",
    type=click.Path(path_type=Path),
    help="TOML secret-classification overrides.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    help="Repository configuration file to load.",
)
def audit(
    output_format: str,
    fail_on: str | None,
    verbose: bool,
    host: str | None,
    use_sudo: bool | None,
    docker_context: str | None,
    project_name: str | None,
    all_projects: bool,
    secret_policy_path: Path | None,
    config_path: Path | None,
) -> None:
    """Audit remote Compose projects without writing anything.

    Uses the same pipeline as generate and compares the captured source with an existing role's
    provenance. Requires --host and exactly one of --project or --all. Text output shows errors
    only; add -v for more, or use --format json.
    """
    if host is None:
        raise click.UsageError(
            "local audit was removed; use --host with exactly one of --project or --all"
        )
    if project_name is None and not all_projects:
        raise click.UsageError("remote audit requires exactly one of --project or --all")
    if project_name is not None and all_projects:
        raise click.UsageError("remote audit accepts only one of --project or --all")

    text_output = output_format == "text"
    if text_output:
        click.echo(f"Discovering projects on {host}...")
    try:
        layout = _layout(config_path, explicit_secret_policy=secret_policy_path, host=host)
        secret_policy = _load_secret_policy(layout.secret_policy)
        result = resolve_remote_projects(
            host,
            project_name=project_name,
            all_projects=all_projects,
            use_sudo=_configured_sudo(use_sudo, layout.host),
            secret_policy=secret_policy,
            docker_context=_docker_context(docker_context, layout.host),
            on_outcome=(
                (
                    lambda outcome: _echo_audit_outcome(
                        _outcome_with_drift(outcome, layout.roles_directory), verbose
                    )
                )
                if text_output
                else None
            ),
        )
        result = _audit_result_with_drift(result, layout.roles_directory)
    except ConfigurationError as error:
        raise _ConfigurationClickError(str(error)) from error
    except Compose2RoleError as error:
        raise click.ClickException(str(error)) from error

    if output_format == "json":
        click.echo(json.dumps(result.as_json()))
    else:
        drifted = sum(
            1
            for project in result.projects
            if project.drift is not None and project.drift.state == "source changed"
        )
        noun = f"ok, {drifted} drift" if all_projects and drifted else "ok"
        _echo_summary(len(result.projects), noun, len(result.failures))
    if result.failures:
        raise click.exceptions.Exit(1)
    findings = tuple(finding for project in result.projects for finding in project.findings)
    if fail_on is not None and _has_failure(findings, fail_on):
        raise click.exceptions.Exit(3)


def _load_secret_policy(secret_policy_path: Path | None) -> SecretPolicy | None:
    selected_path = secret_policy_path
    if selected_path is None:
        environment_path = os.environ.get("COMPOSE2ROLE_SECRET_POLICY")
        selected_path = Path(environment_path) if environment_path else None
    return load_secret_policy(selected_path) if selected_path is not None else None


def _echo_audit_status(name: str, drift: ProjectDrift) -> None:
    _status(True, f"{name} ({_drift_label(drift)})")


def _drift_label(drift: ProjectDrift) -> str:
    if drift.changed:
        return f"{drift.state}: {', '.join(drift.changed)}"
    return drift.state


def _outcome_with_drift(outcome: AuditOutcome, roles_directory: Path) -> AuditOutcome:
    if not isinstance(outcome, ResolvedProject):
        return outcome
    try:
        role_name = normalize_remote_role_name(outcome.project.name)
    except GenerationError:
        drift = ProjectDrift(
            "missing",
            role=outcome.project.name,
            reason="project name cannot be normalized into an Ansible role name",
        )
    else:
        drift = inspect_drift(outcome, roles_directory / role_name)
    return replace(outcome, drift=drift)


def _audit_result_with_drift(result: AuditResult, roles_directory: Path) -> AuditResult:
    outcomes = tuple(
        _outcome_with_drift(outcome, roles_directory) for outcome in result.outcomes
    )
    return AuditResult(
        projects=tuple(
            outcome for outcome in outcomes if isinstance(outcome, ResolvedProject)
        ),
        failures=tuple(
            outcome for outcome in outcomes if isinstance(outcome, ProjectFailure)
        ),
        outcomes=outcomes,
    )


def _echo_audit_outcome(outcome: AuditOutcome, verbose: bool) -> None:
    if isinstance(outcome, ResolvedProject):
        if outcome.drift is not None:
            _echo_audit_status(outcome.project.name, outcome.drift)
        else:
            _status(True, outcome.project.name)
        _echo_findings(outcome.findings, verbose, indent="  ")
        return
    _status(False, f"{outcome.name}: FAILED ({outcome.category}): {outcome.message}")


def _has_failure(findings: tuple[Finding, ...], fail_on: str) -> bool:
    failure_severities = {
        "error": frozenset({Severity.ERROR}),
        "warning": frozenset({Severity.ERROR, Severity.WARNING}),
    }
    return any(finding.severity in failure_severities[fail_on] for finding in findings)


@main.command()
@click.option(
    "--host",
    required=True,
    help="Remote OpenSSH alias or host:port destination.",
)
@click.option(
    "--sudo",
    "use_sudo",
    is_flag=True,
    default=None,
    help="Run the remote Docker command with sudo -n.",
)
@click.option(
    "--docker-context",
    "docker_context",
    help="Remote Docker context to use (default: the remote CLI default).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(("text", "table", "json")),
    default="text",
    help="Output format (table is an alias for text).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    help="Repository configuration file to load.",
)
def discover(
    host: str,
    use_sudo: bool | None,
    docker_context: str | None,
    output_format: str,
    config_path: Path | None,
) -> None:
    """List Compose projects running on a remote host.

    Prints raw project names, statuses, and config files; copy a raw name for use with --project.
    Discovery only reads Docker metadata and never changes the host.
    """
    if output_format in {"text", "table"}:
        click.echo(f"Discovering projects on {host}...")
    try:
        layout = _layout(config_path, host=host)
        projects = discover_projects(
            host,
            use_sudo=_configured_sudo(use_sudo, layout.host),
            docker_context=_docker_context(docker_context, layout.host),
        )
    except ConfigurationError as error:
        raise _ConfigurationClickError(str(error)) from error
    except Compose2RoleError as error:
        raise click.ClickException(str(error)) from error

    if output_format == "json":
        click.echo(json.dumps({"projects": [project.as_json() for project in projects]}))
        return

    for project in projects:
        _status(True, f"{project.name}  {project.status}  {', '.join(project.config_files)}")
    _echo_summary(len(projects), "found", 0)


@main.command()
@click.option(
    "--host",
    help="Also check this remote host (the path discover takes: SSH, daemon, Compose).",
)
@click.option(
    "--sudo",
    "use_sudo",
    is_flag=True,
    default=None,
    help="Run remote check commands with sudo -n (requires --host).",
)
@click.option(
    "--docker-context",
    "docker_context",
    help="Remote Docker context to use (default: the remote CLI default).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    help="Repository configuration file to load.",
)
@click.option(
    "--output",
    "output_directory",
    type=click.Path(path_type=Path),
    help="Roles directory to inspect (default: resolved layout).",
)
@click.option(
    "--secret-policy",
    "secret_policy_path",
    type=click.Path(path_type=Path),
    help="TOML secret-classification overrides.",
)
@click.option(
    "--sops-config",
    "sops_config_path",
    type=click.Path(path_type=Path),
    help="SOPS creation-rule file to validate (or COMPOSE2ROLE_SOPS_CONFIG).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(("text", "json")),
    default="text",
    help="Output format (default: text).",
)
def doctor(
    host: str | None,
    use_sudo: bool | None,
    docker_context: str | None,
    config_path: Path | None,
    output_directory: Path | None,
    secret_policy_path: Path | None,
    sops_config_path: Path | None,
    output_format: str,
) -> None:
    """Check the toolchain, configuration, and generated roles.

    Without --host this checks the controller and the generated roles; with --host it checks only
    the host path discover takes: SSH resolution, the selected daemon, and Docker Compose. Warnings
    never fail the run, a failed required check exits 1, and a configuration error exits 2.
    """
    if host is None and use_sudo:
        raise click.UsageError("--sudo requires --host")
    if host is None and docker_context is not None:
        raise click.UsageError("--docker-context requires --host")
    target = target_for(host)
    configuration_failure = False
    try:
        layout = _layout(
            config_path,
            explicit_output=output_directory,
            explicit_sops_config=sops_config_path,
            explicit_secret_policy=secret_policy_path,
            host=host,
        )
        selected_context = _docker_context(docker_context, layout.host)
    except ConfigurationError as error:
        configuration_failure = True
        report = DoctorReport(
            target=target,
            checks=(
                DoctorCheck(
                    "config",
                    "error",
                    str(error),
                    hint="fix the configuration file or pass --config",
                    required=True,
                ),
            ),
        )
    else:
        report = diagnose(
            layout,
            host=host,
            use_sudo=_configured_sudo(use_sudo, layout.host),
            docker_context=selected_context,
            environ=os.environ,
        )
    if output_format == "json":
        click.echo(json.dumps(report.as_json()))
    else:
        _echo_doctor_report(report)
    if configuration_failure:
        raise click.exceptions.Exit(2)
    if report.failed:
        raise click.exceptions.Exit(1)


def _echo_doctor_report(report: DoctorReport) -> None:
    statuses = {
        "ok": ("✓", "green"),
        "warning": ("!", "yellow"),
        "error": ("✗", "red"),
    }
    for check in report.checks:
        glyph, color = statuses[check.status]
        line = f"{glyph} {check.name}: {check.detail}"
        if check.hint is not None:
            line = f"{line} — {check.hint}"
        click.secho(line, fg=color, color=_color_enabled())
    summary = report.summary()
    click.echo()
    click.echo(
        f"{summary['ok']} ok, {summary['warnings']} warnings, {summary['errors']} errors"
    )
