"""Orchestrate safe, isolated remote role generation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from compose2role.emit import (
    RolePlan,
    diff_plan,
    normalize_remote_role_name,
    preview_remote_role,
    with_encrypted_secrets,
    write_role,
)
from compose2role.errors import GenerationError
from compose2role.remote import resolve_remote_projects
from compose2role.resolve import (
    GeneratedProject,
    GenerationFailure,
    GenerationOutcome,
    GenerationResult,
    PlanDiff,
    ProjectFailure,
    ResolvedProject,
)
from compose2role.secret_policy import SecretPolicy
from compose2role.sops import encrypt_secret_values, resolve_sops_configuration


def generate_remote_projects(
    host: str,
    output_directory: Path,
    *,
    project_name: str | None,
    all_projects: bool,
    use_sudo: bool,
    secret_policy: SecretPolicy | None,
    sops_config_path: Path | None,
    check_only: bool,
    diff_only: bool = False,
    force: bool = False,
    docker_context: str | None = None,
    on_outcome: Callable[[GenerationOutcome], None] | None = None,
) -> GenerationResult:
    """Generate selected remote projects while isolating individual project failures."""
    sops_configuration = resolve_sops_configuration(sops_config_path)
    resolution = resolve_remote_projects(
        host,
        project_name=project_name,
        all_projects=all_projects,
        use_sudo=use_sudo,
        secret_policy=secret_policy,
        docker_context=docker_context,
    )
    prepared = _prepare_projects(resolution.projects, docker_context)
    _mark_output_conflicts(prepared, output_directory)

    outcomes: list[GenerationOutcome] = []

    def record(outcome: GenerationOutcome) -> None:
        outcomes.append(outcome)
        if on_outcome is not None:
            on_outcome(outcome)

    for outcome in resolution.outcomes:
        if isinstance(outcome, ProjectFailure):
            record(
                GenerationFailure(
                    name=outcome.name,
                    role_name=None,
                    category=outcome.category,
                    message=outcome.message,
                )
            )
            continue
        prepared_project = prepared[outcome.project.name]
        if isinstance(prepared_project, GenerationFailure):
            record(prepared_project)
            continue
        if check_only:
            record(
                GeneratedProject(
                    project=outcome,
                    role_name=prepared_project.role_name,
                    checked=True,
                    files=_plan_files(prepared_project.plan),
                )
            )
            continue
        plan = prepared_project.plan
        if plan.secret_values:
            try:
                encrypted_secrets = encrypt_secret_values(sops_configuration, plan.secret_values)
                plan = with_encrypted_secrets(plan, encrypted_secrets)
            except GenerationError as error:
                record(
                    _generation_failure(outcome, prepared_project.role_name, "sops", str(error))
                )
                continue
        plan_diff: PlanDiff | None = None
        if diff_only:
            plan_diff = diff_plan(plan, output_directory / prepared_project.role_name)
            if not force:
                record(
                    GeneratedProject(
                        project=outcome,
                        role_name=prepared_project.role_name,
                        checked=False,
                        files=_plan_files(plan),
                        unchanged=plan_diff.identical,
                        diff=plan_diff,
                        diff_only=True,
                    )
                )
                continue
        try:
            write_result = write_role(plan, output_directory, force=force)
        except GenerationError as error:
            record(
                _generation_failure(outcome, prepared_project.role_name, "output", str(error))
            )
            continue
        record(
            GeneratedProject(
                project=outcome,
                role_name=prepared_project.role_name,
                checked=False,
                files=_plan_files(plan),
                unchanged=write_result.state == "unchanged",
                diff=plan_diff,
            )
        )
    return GenerationResult(outcomes=tuple(outcomes))


@dataclass(frozen=True)
class _PreparedProject:
    """A role plan ready for collision checking and optional output."""

    project: ResolvedProject
    role_name: str
    plan: RolePlan


def _plan_files(plan: RolePlan) -> tuple[str, ...]:
    return tuple(str(generated_file.relative_path) for generated_file in plan.files)


def _prepare_projects(
    projects: tuple[ResolvedProject, ...], docker_context: str | None
) -> dict[str, _PreparedProject | GenerationFailure]:
    prepared: dict[str, _PreparedProject | GenerationFailure] = {}
    for project in projects:
        try:
            role_name = normalize_remote_role_name(project.project.name)
            plan = preview_remote_role(
                project, role_name, docker_context=docker_context
            )
        except GenerationError as error:
            prepared[project.project.name] = _generation_failure(
                project, None, "generation", str(error)
            )
        else:
            prepared[project.project.name] = _PreparedProject(project, role_name, plan)
    return prepared


def _mark_output_conflicts(
    prepared: dict[str, _PreparedProject | GenerationFailure], output_directory: Path
) -> None:
    if output_directory.is_symlink() or (
        output_directory.exists() and not output_directory.is_dir()
    ):
        for project_name, value in prepared.items():
            if isinstance(value, _PreparedProject):
                prepared[project_name] = _generation_failure(
                    value.project,
                    value.role_name,
                    "output",
                    "remote role output must be a directory",
                )
        return

    by_role_name: dict[str, list[_PreparedProject]] = {}
    for value in prepared.values():
        if isinstance(value, _PreparedProject):
            by_role_name.setdefault(value.role_name, []).append(value)
    for candidates in by_role_name.values():
        if len(candidates) > 1:
            for candidate in candidates:
                prepared[candidate.project.project.name] = _generation_failure(
                    candidate.project,
                    candidate.role_name,
                    "output",
                    "normalized remote role name collides with another selected project",
                )
            continue


def _generation_failure(
    project: ResolvedProject,
    role_name: str | None,
    category: str,
    message: str,
) -> GenerationFailure:
    return GenerationFailure(
        name=project.project.name,
        role_name=role_name,
        category=category,
        message=message,
        findings=project.findings,
        classifications=project.classifications,
    )
