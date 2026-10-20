"""Smoke tests: every app package imports and states its purpose."""

import importlib
from types import ModuleType

import pytest

PACKAGES = [
    "airtimesat_platform",
    "airtimesat_platform.gateway",
    "airtimesat_platform.gateway.api",
    "airtimesat_platform.gateway.sitest_port",
    "airtimesat_platform.masker",
    "airtimesat_platform.masker.engine",
    "airtimesat_platform.masker.errors",
    "airtimesat_platform.masker.keys",
    "airtimesat_platform.masker.freetext",
    "airtimesat_platform.masker.logsafe",
    "airtimesat_platform.masker.xmlsafe",
    "airtimesat_platform.masker.fieldmap",
    "airtimesat_platform.masker.fieldmap.loader",
    "airtimesat_platform.masker.fieldmap.model",
    "airtimesat_platform.masker.fieldmap.strict_yaml",
    "airtimesat_platform.masker.tokenize",
    "airtimesat_platform.masker.tokenize.surrogates",
    "airtimesat_platform.masker.tokenize.vault",
    "airtimesat_platform.masker.detect",
    "airtimesat_platform.masker.detect.canary",
    "airtimesat_platform.masker.detect.patterns",
    "airtimesat_platform.masker.detect.scan",
    "airtimesat_platform.recorder",
    "airtimesat_platform.domain",
    "airtimesat_platform.console",
    "airtimesat_platform.archive",
    "airtimesat_platform.common",
    "airtimesat_platform.common.secrets_stdin",
]


@pytest.mark.parametrize("name", PACKAGES)
def test_package_imports_with_docstring(name: str) -> None:
    module = importlib.import_module(name)
    assert module.__doc__
    assert module.__doc__.strip()


@pytest.mark.parametrize(
    "name",
    [
        "airtimesat_platform.gateway",
        "airtimesat_platform.gateway.api",
        "airtimesat_platform.gateway.sitest_port",
        "airtimesat_platform.recorder",
        "airtimesat_platform.domain",
        "airtimesat_platform.archive",
        "airtimesat_platform.common.secrets_stdin",
    ],
)
def test_placeholder_packages_define_nothing_yet(name: str) -> None:
    module = importlib.import_module(name)
    public = [
        attr
        for attr, value in vars(module).items()
        if not attr.startswith("_") and not isinstance(value, ModuleType)
    ]
    assert public == []
