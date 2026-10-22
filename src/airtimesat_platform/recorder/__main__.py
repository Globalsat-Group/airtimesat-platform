"""The recorder's command line: ``python -m airtimesat_platform.recorder`` (design §5.1).

Commands (``inventory add`` and ``note`` arrive in S2 PR D3):

- ``recorder check <plan>...``: see below.
- ``recorder init --data-dir <abs> --backup-dir <abs> [--new-keys]``: create the identity,
  the configuration and the secrets files, once (``init``).
- ``recorder doctor``: read-only checks of the trusted machine (``doctor``).
- ``recorder rekey``: a new identity and passphrase for the secrets files (``init``).
- ``recorder run <plan> [--dry-run]``: run a reviewed plan's reads, or dry-run it (``run``).
- ``recorder keys init``: write four new masking keys to a pipe (``admin``).
- ``recorder backup``: write an age-encrypted vault backup (``admin``).
- ``recorder incident clear <id>``: re-enable the method an incident blocked (``admin``).

``run``, ``backup``, ``incident clear`` and ``doctor`` read the configuration (``config``,
``--config``), which ``init`` writes, and every command but ``check`` runs only on the trusted
machine. Every command exits 0 on success, 1 when refused or
stopped, and 2 on a usage error, and prints codes, never a value.

``recorder check <plan>...`` needs no secret, no vault and no network, so it also runs in CI
and in agent sessions. It prints one line per plan:

- ``OK <plan-id> <sha256-digest>``
- ``REFUSED <path> <CODE> [<location>]``

and exits 0 when every plan is valid, 1 when any is refused, and 2 on a usage error. It
never prints a plan value, not even a refused plan's id: CI logs are stored at GitHub, and a
plan might hold a real identifier. An uncaught exception prints its type and code only.
"""

import argparse
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, TextIO

from airtimesat_platform.gateway.sitest_port import generated_field_map_text
from airtimesat_platform.masker.errors import MaskingError, safe_path
from airtimesat_platform.masker.fieldmap.loader import build_field_map, packaged_overrides
from airtimesat_platform.masker.logsafe import install_excepthook
from airtimesat_platform.recorder import admin, doctor, init
from airtimesat_platform.recorder.config import load_config
from airtimesat_platform.recorder.errors import PlanRefusedError
from airtimesat_platform.recorder.plan import FieldMapContext, check_plan, read_plan_file
from airtimesat_platform.recorder.run import FieldMapSource, run_plan

EXIT_OK: Final = 0
EXIT_REFUSED: Final = 1
EXIT_USAGE: Final = 2


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
    setup = commands.add_parser(
        "init", help="create the identity, configuration and secrets files (trusted machine)"
    )
    setup.add_argument("--data-dir", type=Path, required=True, help="absolute data folder")
    setup.add_argument("--backup-dir", type=Path, required=True, help="absolute backup folder")
    setup.add_argument(
        "--new-keys",
        action="store_true",
        help="make new masking keys for an existing identity (runbook 06 case 4 only)",
    )
    checks = commands.add_parser("doctor", help="read-only checks of the trusted machine")
    rekey = commands.add_parser(
        "rekey", help="new identity and passphrase for the secrets files (runbook 06 case 7)"
    )
    run = commands.add_parser("run", help="run a reviewed plan's reads (trusted machine)")
    run.add_argument("plan", help="the recording plan file")
    run.add_argument("--dry-run", action="store_true", help="check and show; never call IWS")
    keys = commands.add_parser("keys", help="masking keys").add_subparsers(
        dest="action", required=True
    )
    keys.add_parser("init", help="write four new keys to a pipe")
    backup = commands.add_parser("backup", help="write an age-encrypted vault backup")
    incident = commands.add_parser("incident", help="incidents").add_subparsers(
        dest="action", required=True
    )
    clear = incident.add_parser("clear", help="re-enable the method an incident blocked")
    clear.add_argument("id", type=int, help="the incident id")
    for command in (setup, checks, rekey, run, backup, clear):
        command.add_argument("--config", type=Path, help="configuration file")
    return parser


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
            checked = check_plan(
                read_plan_file(path), now=now, field_map=context, field_map_refusal=refusal
            )
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
    stream = out if out is not None else sys.stdout
    command: str = args.command
    if command == "check":
        plans: list[str] = args.plans
        return check(plans, out=stream, now=now(), field_map_source=field_map_source)
    try:
        if command == "keys":
            admin.keys_init(stream)
            return EXIT_OK
        if command == "init":
            init.init(
                args.data_dir,
                args.backup_dir,
                config_path=args.config,
                out=stream,
                new_masker_keys=args.new_keys,
            )
            return EXIT_OK
        if command == "doctor":
            return doctor.doctor(args.config, out=stream)
        if command == "rekey":
            init.rekey(args.config, out=stream, now=now())
            return EXIT_OK
        config = load_config(args.config)
        if command == "run":
            return run_plan(
                Path(args.plan),
                config=config,
                dry_run=args.dry_run,
                out=stream,
                field_map_source=field_map_source,
                now=now,
            )
        if command == "backup":
            path, pruned = admin.backup(config, now())
            stream.write(f"BACKUP_WRITTEN {path.name} pruned={pruned}\n")
            stream.write("Attach this file to the Keeper record (runbook 04).\n")
            return EXIT_OK
        operation = admin.incident_clear(config, args.id, now())
        stream.write(f"INCIDENT_CLEARED {args.id} operation={operation or '-'}\n")
        return EXIT_OK
    except PlanRefusedError as exc:
        stream.write(f"REFUSED {exc.code} {exc.location}".rstrip() + "\n")
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
