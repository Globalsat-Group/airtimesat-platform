"""Phase 2 TAP file archive job.

Copies TAP files to the archive bucket with sha256 checks and file-sequence gap
detection. Imports only ``domain`` and ``common``. Built in stage S1; empty until then.
"""
