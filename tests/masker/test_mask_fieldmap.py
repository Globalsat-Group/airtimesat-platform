"""Field map: UNCLASSIFIED by default, reviewed overrides, strict YAML (design §4.5, §5.2)."""

from collections.abc import Callable

import pytest

from airtimesat_platform.masker.engine import MaskingEngine
from airtimesat_platform.masker.errors import FieldMapError, MaskingError
from airtimesat_platform.masker.fieldmap.loader import (
    build_field_map,
    load_generated,
)
from airtimesat_platform.masker.fieldmap.model import (
    Direction,
    FieldEntry,
    FieldMap,
    Treatment,
    propose,
    sentinel_valid,
    validate_entry,
)
from airtimesat_platform.masker.fieldmap.strict_yaml import StrictYamlError, load_strict
from airtimesat_platform.masker.freetext import Template
from airtimesat_platform.masker.keys import MaskingKeys
from airtimesat_platform.masker.tokenize.vault import InMemoryVaultStore, Vault

HEADER = "format: airtimesat-fieldmap/1\npaths:\n"
OVERRIDES = "format: airtimesat-overrides/1\nentries:\n"


def gen(*lines: str) -> str:
    return HEADER + "".join(f"  - {line}\n" for line in lines)


def ovr(*lines: str) -> str:
    return OVERRIDES + "".join(f"  - {line}\n" for line in lines)


LEAF = "{operation: op, direction: response, path: opResponse/value, xsd_type: %s%s}"
ROOT = "{operation: op, direction: response, path: opResponse, xsd_type: complex}"
ROOT_KEEP = "{operation: op, direction: response, path: opResponse, treatment: KEEP}"


def leaf(xsd_type: str = "string", extra: str = "") -> str:
    return LEAF % (xsd_type, extra)


def leaf_override(rest: str) -> str:
    return "{operation: op, direction: response, path: opResponse/value, " + rest + "}"


def test_synthetic_map_loads(mapped: tuple[FieldMap, list[Template]]) -> None:
    field_map, templates = mapped
    assert "getSubscriberAccount" in field_map.operations()
    assert "*" not in field_map.operations()
    assert [t.template_id for t in templates] == ["TPL-T01", "TPL-T02"]
    entry = field_map.lookup(
        "getSubscriberAccount",
        Direction.RESPONSE,
        "getSubscriberAccountResponse/account[sbdSubscriberAccountImpl]/imei",
    )
    assert entry is not None
    assert entry.treatment is Treatment.T_NUM
    assert entry.id_type == "IMEI"
    fault = field_map.lookup("accountSearch", Direction.FAULT, "Fault/faultstring")
    assert fault is not None
    assert fault.treatment is Treatment.F


def test_unclassified_paths_are_listed(mapped: tuple[FieldMap, list[Template]]) -> None:
    field_map, _ = mapped
    paths = [e.path for e in field_map.unclassified()]
    assert paths == ["getSystemStatusResponse/buildHost"]
    assert field_map.unclassified(["accountSearch"]) == []
    assert len(field_map.unclassified(["getSystemStatus"])) == 1


def test_keep_proposals_have_no_effect_until_adopted() -> None:
    field_map, _ = build_field_map(gen(ROOT, leaf("boolean", ", proposed: KEEP")), ovr(ROOT_KEEP))
    entry = field_map.lookup("op", Direction.RESPONSE, "opResponse/value")
    assert entry is not None
    assert entry.treatment is Treatment.UNCLASSIFIED
    assert [e.path for e in field_map.keep_proposals()] == ["opResponse/value"]
    assert len(field_map.unclassified()) == 1


@pytest.mark.parametrize(
    ("xsd_type", "is_enum", "expected"),
    [
        ("boolean", False, Treatment.KEEP),
        ("dateTime", False, Treatment.KEEP),
        ("decimal", False, Treatment.KEEP),
        ("string", True, Treatment.KEEP),
        ("string", False, None),
        ("int", False, None),
        ("long", False, None),
    ],
)
def test_generator_proposals(xsd_type: str, is_enum: bool, expected: Treatment | None) -> None:
    assert propose(xsd_type, is_enum) is expected


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("a: 1\na: 2\n", "YAML_DUPLICATE_KEY"),
        ("a: &x 1\nb: *x\n", "YAML_ANCHOR"),
        ("a: !!str 1\n", "YAML_TAG"),
        ("base: {a: 1}\nchild:\n  <<: {b: 2}\n", "YAML_MERGE_KEY"),
        ("1: a\n", "YAML_NON_STRING_KEY"),
        ("a: [1, 2\n", "YAML_SYNTAX"),
        ("a: !custom x\n", "YAML_TAG"),
    ],
)
def test_strict_yaml_refusals(text: str, code: str) -> None:
    with pytest.raises(StrictYamlError) as info:
        load_strict(text)
    assert info.value.code == code


def test_strict_yaml_alias_without_anchor_is_refused() -> None:
    with pytest.raises(StrictYamlError):
        load_strict("a: *missing\n")


def test_strict_yaml_size_limit() -> None:
    with pytest.raises(StrictYamlError) as info:
        load_strict("a: " + "x" * (3 * 1024 * 1024))
    assert info.value.code == "YAML_TOO_LARGE"


def test_strict_yaml_loads_plain_documents() -> None:
    assert load_strict("a: [1, two]\nb: {c: true}\n") == {"a": [1, "two"], "b": {"c": True}}


@pytest.mark.parametrize(
    ("generated", "overrides", "code"),
    [
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: UNCLASSIFIED")),
            "FIELDMAP_BAD_TREATMENT",
        ),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: BOGUS")),
            "FIELDMAP_BAD_TREATMENT",
        ),
        (gen(ROOT), ovr(leaf_override("treatment: KEEP")), "OVERRIDE_UNKNOWN_PATH"),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: KEEP, colour: red")),
            "FIELDMAP_SCHEMA",
        ),
        (
            gen(ROOT, leaf("int")),
            ovr(ROOT_KEEP, leaf_override("treatment: D")),
            "FIELDMAP_D_NEEDS_SENTINEL",
        ),
        (
            gen(ROOT, leaf("int")),
            ovr(ROOT_KEEP, leaf_override("treatment: D, sentinel: zero")),
            "FIELDMAP_D_NEEDS_SENTINEL",
        ),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: T-NUM, type: SHOE_SIZE")),
            "FIELDMAP_BAD_TYPE",
        ),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: T-STR, type: IMEI")),
            "FIELDMAP_BAD_TYPE",
        ),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: P-ONE, type: VESSEL")),
            "FIELDMAP_BAD_TYPE",
        ),
        (gen(ROOT, leaf()), ovr(ROOT_KEEP, leaf_override("treatment: C")), "FIELDMAP_BAD_TYPE"),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: G")),
            "FIELDMAP_G_NOT_NUMERIC",
        ),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: N")),
            "FIELDMAP_N_WITHOUT_RULE",
        ),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: TYPED")),
            "FIELDMAP_TYPED_WITHOUT_RULE",
        ),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: F, operational: true")),
            "FIELDMAP_OPERATIONAL_ONLY_FOR_KEEP",
        ),
        (
            gen(ROOT, leaf()),
            ovr(ROOT_KEEP, leaf_override("treatment: KEEP, literals: [X]")),
            "FIELDMAP_LITERALS_ONLY_FOR_C",
        ),
        (gen(ROOT, leaf()), ovr(ROOT_KEEP, ROOT_KEEP), "FIELDMAP_DUPLICATE_PATH"),
        (gen(ROOT, ROOT), ovr(ROOT_KEEP), "FIELDMAP_DUPLICATE_PATH"),
        (gen(ROOT, leaf("blob")), ovr(ROOT_KEEP), "FIELDMAP_BAD_XSD_TYPE"),
        (gen(ROOT, leaf("string", ", proposed: T-NUM")), ovr(ROOT_KEEP), "FIELDMAP_BAD_PROPOSAL"),
        (gen(ROOT, leaf("string", ", treatment: KEEP")), ovr(ROOT_KEEP), "FIELDMAP_SCHEMA"),
        (
            gen("{operation: op, direction: response, path: 'bad path', xsd_type: string}"),
            ovr(),
            "FIELDMAP_BAD_PATH",
        ),
        (
            gen("{operation: op, direction: sideways, path: a, xsd_type: string}"),
            ovr(),
            "FIELDMAP_SCHEMA",
        ),
        (
            gen("{operation: '*', direction: response, path: a, xsd_type: string}"),
            ovr(),
            "FIELDMAP_WILDCARD_OPERATION",
        ),
        (
            gen(
                ROOT, "{operation: op, direction: response, path: opResponse/c, xsd_type: complex}"
            ),
            ovr(
                ROOT_KEEP,
                "{operation: op, direction: response, path: opResponse/c, "
                "treatment: T-STR, type: NAME}",
            ),
            "FIELDMAP_COMPLEX_TREATMENT",
        ),
        (
            gen(
                ROOT, "{operation: op, direction: response, path: opResponse/c, xsd_type: complex}"
            ),
            ovr(
                ROOT_KEEP, "{operation: op, direction: response, path: opResponse/c, treatment: D}"
            ),
            "FIELDMAP_D_REQUIRED_COMPLEX",
        ),
        (
            gen(ROOT, leaf()),
            ovr(
                ROOT_KEEP,
                leaf_override(
                    "treatment: N, embedded: {format: csv, operation_from: x, direction: request}"
                ),
            ),
            "FIELDMAP_N_FORMAT_NOT_SUPPORTED",
        ),
        (
            gen(ROOT, leaf()),
            ovr(
                ROOT_KEEP,
                leaf_override("treatment: N, embedded: {operation_from: x, direction: request}"),
            ),
            "FIELDMAP_SIBLING_NOT_KEPT",
        ),
        (
            gen(ROOT, leaf()),
            ovr(
                ROOT_KEEP,
                leaf_override("treatment: N, embedded: {operation_from: x, direction: fault}"),
            ),
            "FIELDMAP_SCHEMA",
        ),
        (
            gen(ROOT, leaf()),
            ovr(
                ROOT_KEEP,
                leaf_override("treatment: TYPED, typed_by: {sibling: kind, values: {A: T-EMAIL}}"),
            ),
            "FIELDMAP_SIBLING_NOT_KEPT",
        ),
        (
            gen(ROOT, leaf()),
            ovr(
                ROOT_KEEP,
                leaf_override("treatment: TYPED, typed_by: {sibling: kind, values: {A: P-ONE}}"),
            ),
            "FIELDMAP_TYPED_TARGET",
        ),
        (
            gen(ROOT, leaf()),
            ovr(
                ROOT_KEEP, leaf_override("treatment: TYPED, typed_by: {sibling: kind, values: {}}")
            ),
            "FIELDMAP_SCHEMA",
        ),
        ("format: other/1\npaths: []\n", ovr(), "FIELDMAP_FORMAT"),
        (gen(ROOT), "format: other/1\n", "FIELDMAP_FORMAT"),
        ("- just a list\n", ovr(), "FIELDMAP_SCHEMA"),
        (gen(ROOT, leaf("string", ", min_occurs: -1")), ovr(), "FIELDMAP_SCHEMA"),
        (gen(ROOT, leaf("string", ", nillable: maybe")), ovr(), "FIELDMAP_SCHEMA"),
    ],
)
def test_invalid_maps_are_refused(generated: str, overrides: str, code: str) -> None:
    with pytest.raises(FieldMapError) as info:
        build_field_map(generated, overrides)
    assert info.value.code == code


def test_valid_d_variants_load() -> None:
    field_map, _ = build_field_map(
        gen(
            ROOT,
            "{operation: op, direction: response, path: opResponse/a, "
            "xsd_type: int, nillable: true}",
            "{operation: op, direction: response, path: opResponse/b, "
            "xsd_type: int, min_occurs: 0}",
            "{operation: op, direction: response, path: opResponse/c, xsd_type: int}",
        ),
        ovr(
            ROOT_KEEP,
            "{operation: op, direction: response, path: opResponse/a, treatment: D}",
            "{operation: op, direction: response, path: opResponse/b, treatment: D}",
            "{operation: op, direction: response, path: opResponse/c, treatment: D, sentinel: '0'}",
        ),
    )
    assert len(field_map.entries) == 4


def test_duplicate_template_ids_and_bad_templates_are_refused() -> None:
    base = gen(ROOT)
    with pytest.raises(FieldMapError) as info:
        build_field_map(
            base, OVERRIDES + "  []\ntemplates:\n  - {id: T, text: a}\n  - {id: T, text: b}\n"
        )
    assert info.value.code == "TEMPLATE_DUPLICATE_ID"
    for text, code in [
        ("Value {SHOE}", "TEMPLATE_BAD_SLOT"),
        ("Stray } brace", "TEMPLATE_SYNTAX"),
        ("{NAME} and {NAME} and {NAME}", "TEMPLATE_TOO_MANY_LABEL_SLOTS"),
    ]:
        with pytest.raises(FieldMapError) as info:
            Template.compile("T", text)
        assert info.value.code == code


def test_templates_match_whole_values_only() -> None:
    template = Template.compile("T", "Account {CONTRACT} has {{braces}} and {EMAIL}.")
    value = "Account SUB-8000001 has {braces} and person@canary.test."
    slots = template.match(value)
    assert slots is not None
    assert [s[0] for s in slots] == ["CONTRACT", "EMAIL"]
    assert template.match("Prefix " + value) is None
    assert template.match(value + " suffix") is None


def test_load_generated_reads_unbounded_and_defaults() -> None:
    entries = load_generated(gen(leaf("string", ", max_occurs: unbounded, min_occurs: 0")))
    assert entries[0].max_occurs is None
    assert entries[0].min_occurs == 0
    assert entries[0].treatment is Treatment.UNCLASSIFIED


def test_sentinel_validity() -> None:
    assert sentinel_valid("int", "0")
    assert not sentinel_valid("int", " 0")
    assert not sentinel_valid("int", "")
    assert sentinel_valid("boolean", "false")
    assert sentinel_valid("dateTime", "1970-01-01T00:00:00Z")
    assert not sentinel_valid("string", "x")


def test_validate_entry_checks_typed_targets() -> None:
    entry = FieldEntry("op", Direction.RESPONSE, "a", "string", Treatment.T_NUM, "IMEI")
    validate_entry(entry)


def test_engine_refuses_surrogates_that_do_not_fit_numeric_types(
    keys_factory: Callable[[int], MaskingKeys],
) -> None:
    field_map, _ = build_field_map(
        gen(ROOT, leaf("long")), ovr(ROOT_KEEP, leaf_override("treatment: T-NUM, type: ICCID"))
    )
    with pytest.raises(MaskingError) as info:
        MaskingEngine(field_map, Vault(InMemoryVaultStore(), keys_factory(1)))
    assert info.value.code == "FIELDMAP_SURROGATE_DOES_NOT_FIT"
    field_map, _ = build_field_map(
        gen(ROOT, leaf("int")), ovr(ROOT_KEEP, leaf_override("treatment: T-EMAIL"))
    )
    with pytest.raises(MaskingError) as info:
        MaskingEngine(field_map, Vault(InMemoryVaultStore(), keys_factory(1)))
    assert info.value.code == "FIELDMAP_TYPE_MISMATCH"
