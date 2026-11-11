"""The source-faithful role emitter for remote generation.

This module is the stable import surface; the rendering implementation lives in
:mod:`compose2role.remote_emit`.
"""

from __future__ import annotations

from compose2role.remote_emit import (
    GeneratedFile,
    PlanComparison,
    RolePlan,
    RoleWriteResult,
    compare_plan,
    diff_plan,
    external_prerequisites,
    normalize_remote_role_name,
    preview_remote_role,
    with_encrypted_secrets,
    write_role,
)
from compose2role.resolve import FileDiff, PlanDiff

__all__ = [
    "FileDiff",
    "GeneratedFile",
    "PlanComparison",
    "PlanDiff",
    "RolePlan",
    "RoleWriteResult",
    "compare_plan",
    "diff_plan",
    "external_prerequisites",
    "normalize_remote_role_name",
    "preview_remote_role",
    "with_encrypted_secrets",
    "write_role",
]
