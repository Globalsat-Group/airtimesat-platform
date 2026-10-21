"""Recorder: the CTO-only command-line tool that records SITEST through the masker.

Runs only on the CTO's trusted machine, from a clean checkout of a commit on ``main``, and
only from a recording plan the CTO reviewed and merged (``recording-plans/``). It reaches
IWS only through ``airtimesat_platform.gateway.sitest_port`` and writes masked exchanges
only. Imports only ``common``, ``masker`` and ``gateway.sitest_port``. Design
``docs/design/s2-recorder-masker.md`` §5, §7.2.

- ``plan``: the strict plan loader, schema, references and canonical digest.
- ``policy.allowlist``: the read allowlist and its per-method limits.
- ``policy.hard_blocks``: DEACTIVE, bulk, always-refused methods and request shape.
- ``run``: ``recorder run`` for reads, with process hardening and fail-closed handling.
- ``store``: the SQLite vault store, run log, incidents and (for D3) test inventory.
- ``checkout``, ``output``, ``config``, ``admin``: the git checks, the staged files and scans,
  the configuration file, and ``keys init``, ``backup`` and ``incident clear``.
- ``__main__``: the command line. ``recorder check`` needs no secret, no vault and no
  network, so it also runs in CI and agent sessions; every other command runs only on the
  trusted machine.
"""
