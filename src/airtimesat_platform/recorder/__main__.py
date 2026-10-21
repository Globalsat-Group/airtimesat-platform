"""The recorder's command line: ``python -m airtimesat_platform.recorder`` (design §5.1).

Only ``check`` exists in this stage (S2 PR D1). ``run``, ``inventory add``, ``note``,
``incident clear``, ``backup`` and ``keys init`` arrive in D2 and D3.

``recorder check <plan>...`` needs no secret, no vault and no network, so it also runs in CI
and in agent sessions. It prints one line per plan:

- ``OK <plan-id> <sha256-digest>``
- ``REFUSED <path> <CODE> [<location>]``

and exits 0 when every plan is valid, 1 when any is refused, and 2 on a usage error. It
never prints a plan value, not even a refused plan's id: CI logs are stored at GitHub, and a
plan might hold a real identifier. An uncaught exception prints its type and code only.
"""

import argparse
import errno
import os
import stat
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Final, TextIO

from airtimesat_platform.gateway.sitest_port import generated_field_map_text
from airtimesat_platform.masker.errors import MaskingError, safe_path
from airtimesat_platform.masker.fieldmap.loader import build_field_map, packaged_overrides
from airtimesat_platform.masker.logsafe import install_excepthook
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.plan import MAX_PLAN_BYTES, FieldMapContext, check_plan

EXIT_OK: Final = 0
EXIT_REFUSED: Final = 1
EXIT_USAGE: Final = 2

# Returns the generated field map's text and the overrides' text, or None while the
# generated map does not exist (until the WSDL harvest, PR W).
FieldMapSource = Callable[[], tuple[str, str] | None]


def packaged_field_map() -> tuple[str, str] | None:
    """Return the gateway's generated field map and the masker's reviewed overrides."""
    generated = generated_field_map_text()
    if generated is None:
        return None
    return generated, packaged_overrides()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _shown_path(path: str) -> str:
    """Show the path given on the command line, with any segment that could carry data as ?."""
    return "/".join(safe_path([part]) if part else "" for part in path.split("/"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recorder",
        description="CTO-only SITEST recorder (design s2-recorder-masker §5).",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser(
        "check",
        help="check recording plans: no secret, no vault, no network",
        description="Check recording plans. Exit 0: all valid; 1: any refused; 2: usage.",
    )
    check.add_argument("plans", nargs="+", metavar="plan", help="a recording plan file")
    return parser


def _read(path: str) -> str:
    """Read a plan: a regular file, never through a symlink, at most ``MAX_PLAN_BYTES``.

    A symlink would make CI judge a file outside ``recording-plans/`` that a later pull
    request can change unseen, and a FIFO or a device could stall or flood the check.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PlanRefusedError("PLAN_NOT_REGULAR_FILE") from None
        raise PlanRefusedError("PLAN_UNREADABLE") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PlanRefusedError("PLAN_NOT_REGULAR_FILE")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAX_PLAN_BYTES + 1)
    except OSError:
        raise PlanRefusedError("PLAN_UNREADABLE") from None
    finally:
        os.close(fd)
    if len(data) > MAX_PLAN_BYTES:
        raise PlanRefusedError("PLAN_TOO_LARGE")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise PlanRefusedError("PLAN_NOT_UTF8") from None


def _field_map(source: FieldMapSource) -> tuple[FieldMapContext | None, str]:
    """Load the field map once for the run; on failure, the code every plan gets."""
    try:
        texts = source()
        if texts is None:
            return None, "FIELD_MAP_MISSING"
        field_map, _ = build_field_map(*texts)
        # The engine refuses a map whose surrogates cannot fit their XSD types.
        return FieldMapContext(field_map), ""
    except MaskingError:
        return None, "FIELD_MAP_INVALID"


def check(
    paths: Sequence[str],
    *,
    out: TextIO,
    now: datetime,
    field_map_source: FieldMapSource,
) -> int:
    """Check each plan and print its line; return the exit code."""
    context, refusal = _field_map(field_map_source)
    status = EXIT_OK
    for path in paths:
        try:
            checked = check_plan(_read(path), now=now, field_map=context, field_map_refusal=refusal)
        except PlanRefusedError as exc:
            line = f"REFUSED {_shown_path(path)} {exc.code} {exc.location}".rstrip()
            status = EXIT_REFUSED
        except Exception:  # fail closed: an unexpected error refuses the plan, quietly
            line = f"REFUSED {_shown_path(path)} CHECK_FAILED"
            status = EXIT_REFUSED
        else:
            line = f"OK {checked.plan.id} {checked.digest}"
        out.write(line + "\n")
    return status


def main(
    argv: Sequence[str] | None = None,
    *,
    out: TextIO | None = None,
    now: Callable[[], datetime] = _utc_now,
    field_map_source: FieldMapSource = packaged_field_map,
) -> int:
    """Run the command line; return the exit code."""
    install_excepthook()
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    plans: list[str] = args.plans
    return check(
        plans,
        out=out if out is not None else sys.stdout,
        now=now(),
        field_map_source=field_map_source,
    )


if __name__ == "__main__":
    sys.exit(main())
