"""Domain errors reported by the command-line interface."""


class Compose2RoleError(Exception):
    """Base class for expected compose2role failures."""


class ConfigurationError(Compose2RoleError):
    """The repository configuration or Ansible layout is invalid or unreadable."""


class DockerContextError(Compose2RoleError):
    """The selected Docker context name is not a valid one."""


class ComposeParseError(Compose2RoleError):
    """The compose document is invalid or outside the supported subset."""


class GenerationError(Compose2RoleError):
    """The target Ansible role cannot be generated safely."""


class RemoteCommandError(Compose2RoleError):
    """An SSH-mediated Docker Compose command failed."""

    def __init__(self, message: str, category: str = "remote-command") -> None:
        super().__init__(message)
        self.category = category


class SecretPolicyError(Compose2RoleError):
    """The controller-side secret-classification policy is invalid."""
