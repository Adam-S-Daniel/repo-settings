#!/usr/bin/env python3
"""
set_privacy_denylist.py -- store the fleet's privacy denylist as the SOURCE of
the `secrets` fan-out (docs/decisions/0020, issue #231).

Reads the denylist on stdin (or from --file) and stores it as the
PRIVACY_DENYLIST secret of the apply environments of this repo, then records
when it did so in the repo variable PRIVACY_DENYLIST_UPDATED_AT. The next
`repo-settings` run compares every repo's copy against that timestamp and
refreshes the missing or older ones.

    ~/bin/show-denylist | python3 scripts/set_privacy_denylist.py
    python3 scripts/set_privacy_denylist.py --file ~/.config/privacy-denylist.txt

Needs `gh` signed in with admin rights on the repo (environment secrets and
repo variables). The value goes to `gh` on stdin only, so it never appears in
a command line, and nothing it prints is passed on unredacted: this script
prints environment names and a timestamp, never a pattern.

A --file inside a git work tree is refused: a denylist next to code is one
`git add` from public history.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_REPO = "Adam-S-Daniel/repo-settings"
DEFAULT_ENVIRONMENTS = ("fleet-apply", "fleet-apply-auto")
SECRET_NAME = "PRIVACY_DENYLIST"
UPDATED_VARIABLE = "PRIVACY_DENYLIST_UPDATED_AT"


class SetError(Exception):
    """A refusal or failure; the message is safe to print (no value in it)."""


def inside_git_work_tree(path: Path) -> bool:
    """True when `path` (a file or a folder) is inside a git work tree. A
    machine without git has no work tree to be inside."""
    folder = path if path.is_dir() else path.parent
    try:
        proc = subprocess.run(
            ["git", "-C", str(folder), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def read_source(file: Path | None, stdin) -> str:
    """The denylist text, from --file or stdin. Refuses a file in a work tree,
    an empty value and an interactive terminal."""
    if file is not None:
        resolved = file.expanduser().resolve()
        if inside_git_work_tree(resolved):
            raise SetError(
                f"refusing {resolved}: it is inside a git work tree. Keep the "
                f"denylist outside every repository."
            )
        value = resolved.read_text(encoding="utf-8")
    else:
        if stdin.isatty():
            raise SetError("pipe the denylist in on stdin, or pass --file")
        value = stdin.read()
    if not value.strip():
        raise SetError("the denylist is empty")
    return value


def redact(text: str, value: str) -> str:
    """Remove the value, and each of its lines, from text bound for a log."""
    for part in sorted({value, *value.splitlines()}, key=len, reverse=True):
        if part.strip():
            text = text.replace(part, "[redacted]")
    return text


def _gh(args: list[str], value: str, stdin_text: str | None) -> None:
    proc = subprocess.run(["gh", *args], input=stdin_text,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        detail = redact((proc.stderr or proc.stdout).strip(), value)
        raise SetError(f"gh {' '.join(args[:2])} failed: {detail}")


def store(value: str, repo: str, environments: tuple[str, ...],
          now: datetime | None = None) -> str:
    """Store the secret in every environment, then the timestamp variable.
    Returns the timestamp. The timestamp is taken after the secrets are
    written, so no copy a later run makes can look older than it."""
    for env in environments:
        _gh(["secret", "set", SECRET_NAME, "--repo", repo, "--env", env], value, value)
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    _gh(["variable", "set", UPDATED_VARIABLE, "--repo", repo, "--body", stamp], value, None)
    return stamp


def main(argv: list[str] | None = None, stdin=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--file", type=Path, help="read the denylist from this file "
                        "(outside any git work tree) instead of stdin")
    parser.add_argument("--repo", default=DEFAULT_REPO,
                        help=f"repo holding the apply environments (default {DEFAULT_REPO})")
    parser.add_argument("--environment", action="append", dest="environments",
                        help="apply environment to store it in; repeatable "
                             f"(default {', '.join(DEFAULT_ENVIRONMENTS)})")
    args = parser.parse_args(argv)
    environments = tuple(args.environments or DEFAULT_ENVIRONMENTS)
    try:
        value = read_source(args.file, stdin if stdin is not None else sys.stdin)
        stamp = store(value, args.repo, environments)
    except SetError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
    print(f"stored {SECRET_NAME} in {', '.join(environments)} of {args.repo}")
    print(f"{UPDATED_VARIABLE} = {stamp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
