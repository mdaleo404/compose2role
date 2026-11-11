[![Licence](https://img.shields.io/badge/GPL--3.0--or--later-orange?label=Licence)](https://git.sysmd.uk/mdaleo404/compose2role/src/branch/main/LICENSE)
[![Gitea Release](https://img.shields.io/gitea/v/release/mdaleo404/compose2role?gitea_url=https%3A%2F%2Fgit.sysmd.uk%2F&style=flat&color=orange&logo=gitea)](https://git.sysmd.uk/mdaleo404/compose2role/releases)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-blue?logo=pre-commit&style=flat)](https://git.sysmd.uk/mdaleo404/compose2role/src/branch/main/.pre-commit-config.yaml)

# compose2role

Generate Ansible roles from Docker Compose projects discovered on remote hosts.

`compose2role` inspects a Docker Compose project over SSH and writes an Ansible role that
reproduces it. The role restores the captured Compose files, dotenv files, and file-backed secrets
byte for byte (comments, quoting, ordering, and line endings included), then applies them with
`docker compose` under the original project name. Applying a role to its source host is an in-place
adoption, not a migration.

It is deliberately **not** a Compose rewriter, normalizer, or migration tool. It is remote-only:
`generate` and `audit` require `--host` plus exactly one of `--project` or `--all`; a local-stack
invocation is a usage error. The daemon is named, not guessed (`--docker-context`), and privilege is
explicit (`--sudo` is never inferred).

Angle-bracket tokens such as `<host>`, `<project>`, and `<role>` are placeholders.

## Documentation

The in-depth reference lives on the [SysMD](https://www.sysmd.uk) site. This README covers the model, requirements, quick
start, and generated role at a glance.

| Page | Covers |
| --- | --- |
| [Installation and configuration](https://www.sysmd.uk/docs/compose2role/install/) | Requirements, install, configuration discovery, environment variables |
| [Remote workflow](https://www.sysmd.uk/docs/compose2role/workflow/) | Discovery, capture, Docker context selection, audit, safe regeneration |
| [Command reference](https://www.sysmd.uk/docs/compose2role/reference/) | Options, JSON output, exit codes |
| [Generated role reference](https://www.sysmd.uk/docs/compose2role/generated-role/) | Layout, variables, tasks, playbook boundary |
| [Secrets and SOPS](https://www.sysmd.uk/docs/compose2role/secrets/) | Capture, classification, secret policy, encryption |
| [Safety and limitations](https://www.sysmd.uk/docs/compose2role/safety/) | Security boundaries, refusals, unsupported features |
| [Troubleshooting](https://www.sysmd.uk/docs/compose2role/troubleshooting/) | SSH, Docker, SOPS, drift, and policy failures |
| [Development and validation](https://www.sysmd.uk/docs/compose2role/development/) | Tests, linting, type checks, Ansible validation |

## What it does

- Discovers Compose projects that a remote Docker daemon already knows about.
- Captures the ordered Compose files, the root `.env`, contained `env_file` inputs, and contained
  file-backed Compose secrets.
- Canonicalizes the project with the remote Compose implementation and classifies effective
  environment values as secret or plain.
- Reports stable, value-free `C2Rxxx` findings and audits drift against an existing role.
- Renders the complete plan before touching the output directory, writes atomically, and refuses to
  overwrite a differing or unmanaged role unless `--force` is given.
- Records the selected Docker context so the role deploys to the same daemon.

It does not read or convert local Compose stacks, rewrite captured source, copy bind-mounted data,
follow paths or symlinks outside the project root, support Compose `include`, build contexts,
service `extends`, `profiles`, file-backed configs, or secret-shaped non-environment mapping keys,
create or guess a SOPS configuration, persist plaintext secret values, tear down an existing stack,
or generate playbooks.

## Requirements

- **Controller** — Python >= 3.12, an OpenSSH client, `sops`, and `gpg` when your SOPS backend uses
  it.
- **Target host** — a running Docker daemon with Compose v2 or newer, an SSH account that can run
  `docker compose ls`, `docker compose config`, and `docker ps`, and passwordless `sudo -n` when
  `--sudo` is selected.
- **SOPS** — an operator-owned configuration with a creation rule matching `vars/secrets.sops.yml`.
- **To apply generated roles** — Ansible and the collections the role declares
  (`community.docker` always, `community.sops` when the role contains secrets). Neither Ansible nor
  its collections are needed to generate roles.

Rootless daemons are common; name the daemon with a Docker context. See
[Docker context selection](https://www.sysmd.uk/docs/compose2role/workflow/#docker-context-selection).

## Install

### From PyPI

```console
pipx install compose2role
# or
pip install compose2role
```

`pip` installs only the Python package. `ssh` and `sops` are external binaries and must already be
on `PATH`; `gpg` is needed when your SOPS backend uses it. Ansible and its collections are not
needed to generate roles.

### From source

```console
poetry install
poetry run compose2role --version
```

The package installs a `compose2role` console script. Examples in this document use
`poetry run compose2role` because they assume a checkout; if you installed the published package,
run `compose2role` directly.

For generated-role validation, install the pinned test collections into the checkout:

```console
poetry run ansible-galaxy collection install \
  --requirements-file tests/requirements.yml --collections-path collections
```

`collections/` is local, gitignored test state.

## Quick start

Replace the placeholders with your own host, raw project name, role name, and paths. Each step is
safe to repeat.

### 1. Check the toolchain

```console
poetry run compose2role doctor --host <host> \
  --sops-config <path/to/.sops.yaml>
```

A green host result means `discover` will reach the same daemon. `doctor` prints one line per check
with a remediation hint, then `N ok, N warnings, N errors`.

### 2. Discover projects

```console
poetry run compose2role discover --host <host> --docker-context <context>
```

Copy the raw project name exactly; it is the value for `--project`. Use `--format json` for
machine-readable output, or omit `--docker-context` to use the remote CLI's default context.

### 3. Audit before writing

```console
poetry run compose2role audit --host <host> --project <project> -v
```

Audit resolves the project through the same pipeline as generation, reports findings, and compares
the captured source with any existing role. It writes nothing and never encrypts anything.

### 4. Preview the role

```console
poetry run compose2role generate --host <host> --project <project> \
  --output <path/to/roles> --sops-config <path/to/.sops.yaml> --check
```

`--check` renders the full plan and lists planned files without writing. Use `--diff` instead to
review value-free `added`, `changed`, `unchanged`, and `withheld` paths.

### 5. Generate the role

```console
poetry run compose2role generate --host <host> --project <project> \
  --output <path/to/roles> --sops-config <path/to/.sops.yaml>
```

An unchanged project prints `unchanged` and writes nothing. A differing or unmanaged role is
refused unless `--force` is given, which backs up the previous role and swaps atomically. Use
`--all` instead of `--project` to generate every discovered project; each succeeds or fails
independently.

### 6. Write and run a playbook

Generation writes roles only. Write the play that applies one:

```yaml
---
- name: Deploy <role>
  hosts: <host>
  become: true          # rootful daemons; remove or replace it for a rootless daemon
  roles:
    - <role>
```

The role's tasks are tagged `source`, `secrets`, and `compose`:

```console
ansible-playbook -i <inventory> <your-playbook>.yml --roles-path <roles> --tags source,secrets
ansible-playbook -i <inventory> <your-playbook>.yml --roles-path <roles> --tags compose
```

To deploy to a different host, override `<role>_project_dir` and any external prerequisites.

## Commands at a glance

| Command | Purpose | Key options |
| --- | --- | --- |
| `doctor` | Diagnose the controller, configuration, roles, or a remote host. | `--host`, `--sudo`, `--docker-context`, `--format` |
| `discover` | List the projects the remote daemon knows about. | `--host`, `--docker-context`, `--format text\|table\|json` |
| `audit` | Resolve a project, report findings, and compare drift; writes nothing. | `--host`, `--project`/`--all`, `--fail-on`, `-v` |
| `generate` | Render and write roles. | `--host`, `--project`/`--all`, `--output`, `--sops-config`, `--check`, `--diff`, `--force` |

All commands accept `--config` where meaningful. See the
[command reference](https://www.sysmd.uk/docs/compose2role/reference/) for the full option list,
JSON shapes, and exit codes.

## Generated role

```text
<roles>/<role>/
├── defaults/main.yml
├── tasks/main.yml
├── meta/main.yml
├── meta/requirements.yml
├── .compose2role.json
├── templates/                  # captured source, mirroring original relative paths
└── vars/
    └── secrets.sops.yml        # only when the role has secrets
```

`meta/requirements.yml` declares the collections the role needs. Install them on the Ansible
controller that applies the role:

```console
ansible-galaxy collection install -r <roles>/<role>/meta/requirements.yml
```

`defaults/main.yml` defines `<role>_project_dir`, the original raw name as
`<role>_compose_project_name`, and `<role>_docker_context` when one was selected. Captured non-secret
values become lower-case role variables; secret values live only in `vars/secrets.sops.yml`.
`.compose2role.json` records provenance: generator version, mode, names, source paths, external
prerequisites, and per-file hashes, never a secret value.

See the [generated role reference](https://www.sysmd.uk/docs/compose2role/generated-role/) for
variable naming, task details, and linting.

## Safety

- Secret values may exist in controller memory while the plan is rendered, but never reach plaintext
  role files, defaults, templates, provenance, logs, diffs, findings, exception text, or command
  output. Only encrypted `vars/secrets.sops.yml` is persisted.
- The SOPS configuration is operator-owned; the tool never copies it or invents recipients.
- Captured inputs must be regular, non-symlinked files inside the project root. Bind-mounted data is
  never read or copied.
- Generated roles apply with `state: present` and `remove_orphans: false`; they never remove
  services, volumes, networks, or images.

See [Safety and limitations](https://www.sysmd.uk/docs/compose2role/safety/) for the full refusal
rules and [Secrets and SOPS](https://www.sysmd.uk/docs/compose2role/secrets/) for classification
and policy details.

## Development

```console
poetry run pre-commit run --all-files
poetry run pytest -q
poetry run ruff check .
poetry run mypy
```

The pre-commit hooks run ruff, mypy, and file hygiene; pytest is not a hook. Enable them on
commit once with `poetry run pre-commit install`.

The suite runs real `ansible-lint` and `ansible-playbook --syntax-check` against generated roles.
Without the pinned collections in `collections/`, those tests fail. Remote tests stub `ssh` and
`sops` through `PATH`, so they need no real host, network, sudo, or secrets. `mypy` checks only
`src` in strict mode.

## Support

If you find **compose2role** useful, consider supporting its development:

[![Support me on Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/mdaleo404)
