"""Masking engine: replaces every identifier before SITEST data reaches an agent or git.

Pure functions over XML, a field map and a vault store; no network I/O (design
``docs/design/s2-recorder-masker.md`` §3, §4, §8). The recorder uses it; it never uses the
recorder. Imports nothing from other app packages except ``common``, and may import
``lxml``.

- ``engine``: mask a response, unmask a request, run the runtime detector.
- ``fieldmap``: the generated map (UNCLASSIFIED by default) merged with the reviewed
  ``overrides.yaml``; a strict YAML loader.
- ``tokenize``: surrogate formats, keyed derivation, check digits, and the vault.
- ``detect``: the §8.1 detectors, field-aware scanning, known values, the canary range.
- ``freetext``: reviewed message templates for free text.
- ``xmlsafe``: the safe XML parser and serialization.
- ``logsafe``: allowlisted logging and safe exception reports for the recorder.
"""
