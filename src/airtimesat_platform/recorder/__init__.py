"""Recorder: the CTO-only command-line tool that records SITEST through the masker.

Runs only on the CTO's trusted machine, from a clean checkout of a commit on ``main``, and
only from a recording plan the CTO reviewed and merged (``recording-plans/``). It reaches
IWS only through ``airtimesat_platform.gateway.sitest_port`` and writes masked exchanges
only. Imports only ``common``, ``masker`` and ``gateway.sitest_port``. Design
``docs/design/s2-recorder-masker.md`` §5, §7.2.

- ``plan``: the strict plan loader, schema, references and canonical digest.
- ``policy.allowlist``: the read allowlist and its per-method limits.
- ``policy.hard_blocks``: DEACTIVE, bulk, always-refused methods and request shape.
- ``__main__``: the command line. Only ``recorder check`` exists so far (S2 PR D1); it needs
  no secret, no vault and no network, and also runs in CI and agent sessions.
"""
