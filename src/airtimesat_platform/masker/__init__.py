"""Masking engine: replaces every identifier before SITEST data reaches an agent or git.

Pure functions over XML, a field map and a vault store; no network I/O. The recorder uses
it; it never uses the recorder. Imports nothing from other app packages except ``common``,
and may import ``lxml``. Built in stage S2; empty until then.
"""
