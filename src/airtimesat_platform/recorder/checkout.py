"""Reviewed code only: the git checks before a run (design §5.1 step 1, §6.5).

A live run needs a clean working tree whose ``HEAD`` is one of ``origin/main``'s first-parent
commits (checked after ``git fetch origin main``), and a plan file under ``recording-plans/``
tracked in that commit. A dry run needs the same clean checkout of ``main``, but its plan file
may be unmerged: if it sits inside the checkout, it alone is left out of the clean-tree check.
``recorder init`` makes the dry-run checks with no plan. Either way, the recorder's own code
must be imported from that checkout, and no tracked file may be marked assume-unchanged or
skip-worktree (``git status`` does not see their edits). Git never prompts for credentials
(``GIT_TERMINAL_PROMPT=0``), and its standard input is empty, never the secrets pipe: a fetch
that needs input fails with ``GIT_FETCH_FAILED``. Every fetch ends before the recorder's first
passphrase prompt, so a prompt from the CTO's own ssh setup can never meet an age prompt.

These checks live in the code being run, so they catch mistakes, not a malicious commit; the
CTO's merge check before each session is the control (runbook ``03`` Part C).
"""

import os
import subprocess
from pathlib import Path
from typing import Final

from airtimesat_platform.recorder.errors import RecorderError

GIT_TIMEOUT_S: Final = 120
PLANS: Final = Path("recording-plans")
# The remote-tracking ref by its full name: a local branch or tag named origin/main would win
# over the short name.
ORIGIN_MAIN: Final = "refs/remotes/origin/main"
# This file, as imported: the code that runs must come from the checkout it checks.
CODE: Final = Path(__file__)


def _git_env() -> dict[str, str]:
    """No credential prompt from git; the CTO's own ssh settings are left as they are."""
    return {**os.environ, "GIT_TERMINAL_PROMPT": "0"}


def git(checkout: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git in ``checkout`` with fixed arguments; never through a shell."""
    try:
        return subprocess.run(  # noqa: S603 - fixed program, arguments from this module
            ["git", "-C", str(checkout), *args],  # noqa: S607 - git from PATH, like the Makefile
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=GIT_TIMEOUT_S,
            stdin=subprocess.DEVNULL,
            env=_git_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RecorderError("GIT_FAILED") from None


def code_checkout(code: Path) -> Path:
    """Return the checkout that ``code`` (``<checkout>/src/<package>/recorder/<file>``) is in."""
    return code.resolve().parents[3]


def verify_checkout(
    checkout: Path, plan_path: Path | None, *, dry_run: bool, code: Path = CODE
) -> str:
    """Refuse a run from anything but reviewed code; return ``HEAD``'s commit SHA.

    ``plan_path`` is ``None`` only for ``recorder init``, which makes the dry-run checks.
    """
    checkout = checkout.resolve()
    if not code.resolve().is_relative_to(checkout / "src"):
        raise RecorderError("CODE_NOT_FROM_CHECKOUT")
    plan = plan_path.resolve() if plan_path is not None else None
    inside = plan is not None and plan.is_relative_to(checkout)
    if not dry_run:
        if plan is None or not inside:
            raise RecorderError("PLAN_NOT_IN_CHECKOUT")
        if plan.relative_to(checkout).parent != PLANS:
            raise RecorderError("PLAN_NOT_IN_PLANS_FOLDER")
    fetch = git(checkout, "fetch", "--quiet", "origin", f"+refs/heads/main:{ORIGIN_MAIN}")
    if fetch.returncode != 0:
        raise RecorderError("GIT_FETCH_FAILED")
    status = ["status", "--porcelain", "--untracked-files=all"]
    if dry_run and plan is not None and inside:
        status += ["--", ".", f":(exclude,literal){plan.relative_to(checkout).as_posix()}"]
    result = git(checkout, *status)
    if result.returncode != 0 or result.stdout.strip():
        raise RecorderError("CHECKOUT_NOT_CLEAN")
    # ls-files -v tags an assume-unchanged file in lower case and a skip-worktree file "S".
    hidden = git(checkout, "ls-files", "-v")
    if hidden.returncode != 0 or any(
        line[:1].islower() or line[:1] == "S" for line in hidden.stdout.splitlines()
    ):
        raise RecorderError("CHECKOUT_NOT_CLEAN")
    if not dry_run and plan is not None:
        tracked = git(checkout, "ls-files", "--error-unmatch", "--", str(plan))
        if tracked.returncode != 0:
            raise RecorderError("PLAN_NOT_MERGED")
    head = git(checkout, "rev-parse", "--verify", "HEAD^{commit}")
    sha = head.stdout.strip()
    if head.returncode != 0 or len(sha) not in (40, 64):
        raise RecorderError("GIT_FAILED")
    # main's own commits only: a commit from a merged branch was never reviewed as a tree.
    main = git(checkout, "rev-list", "--first-parent", ORIGIN_MAIN)
    if main.returncode != 0 or sha not in main.stdout.split():
        raise RecorderError("HEAD_NOT_ON_MAIN")
    return sha
