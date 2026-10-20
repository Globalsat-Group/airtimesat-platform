"""Recorder and masker: the only path from agents to SITEST.

Records SITEST traffic and masks identifiers before anything reaches an agent or git.
Imports nothing from other app packages except ``common``. Built in stage S2; empty
until then.
"""
