"""Recorder: the CTO-only command-line tool that records SITEST through the masker.

Runs only on the CTO's trusted machine, from a clean checkout of a commit on ``main``, and
only from a recording plan the CTO reviewed and merged (``recording-plans/``). It reaches
IWS only through ``airtimesat_platform.gateway.sitest_port`` and writes masked exchanges
only. Imports only ``common``, ``masker`` and ``gateway.sitest_port``. Built in stage S2
(design ``docs/design/s2-recorder-masker.md`` §5, §7.2); empty until then.
"""
