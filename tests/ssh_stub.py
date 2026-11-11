"""Adapters that let one-shot SSH test stubs serve the framed source session."""

from __future__ import annotations

from pathlib import Path
from shlex import quote


def legacy_source_session_bridge(legacy_ssh: Path) -> str:
    """Wrap a one-shot SSH fake so the resolver can keep one real source session open."""
    return f"""\
#!/bin/sh
legacy={quote(str(legacy_ssh))}

case "$*" in
  *"sh -s")
    IFS= read -r first_line || exit 97
    if [ "$first_line" != '# compose2role-source-session-v1' ]; then
      (printf '%s\\n' "$first_line"; cat) | "$legacy" "$@"
      exit $?
    fi
    while IFS= read -r line; do
      [ "$line" = '# compose2role-source-session-ready' ] && break
    done
    IFS= read -r invocation || exit 97
    [ "$invocation" = main ] || exit 97
    printf '%s\\n' ready
    while IFS=' ' read -r marker request_id operation extra; do
      [ "$marker" = request ] || exit 97
      [ -n "$request_id" ] && [ -z "$extra" ] || exit 97
      IFS= read -r path || exit 97
      IFS= read -r root || exit 97
      IFS= read -r trailer || exit 97
      [ "$trailer" = "end $request_id" ] || exit 97
      encoded=$(printf '%s\\n%s\\n%s\\n' "$operation" "$path" "$root" | base64 | tr -d '\\n')
      response=$(printf '%s\\n%s\\n%s\\n' x "$encoded" y | "$legacy" "$@")
      status=$?
      [ "$status" -eq 0 ] || exit "$status"
      case "$operation" in
        stat)
          case "$response" in
            escape|file|missing|other|symlink)
              printf 'result %s %s\\nend %s\\n' "$request_id" "$response" "$request_id"
              ;;
            *) exit 97 ;;
          esac
          ;;
        capture)
          header=$(printf '%s\\n' "$response" | sed -n '1p')
          case "$header" in
            file[[:space:]]*)
              content=$(printf '%s\\n' "$response" | sed '1d')
              printf 'result %s %s\\n%s\\nend %s\\n' \
                "$request_id" "$header" "$content" "$request_id"
              ;;
            escape|missing|other|symlink)
              printf 'result %s %s\\nend %s\\n' "$request_id" "$header" "$request_id"
              ;;
            *) exit 97 ;;
          esac
          ;;
        *) exit 97 ;;
      esac
    done
    exit 0
    ;;
  *) exec "$legacy" "$@" ;;
esac
"""
