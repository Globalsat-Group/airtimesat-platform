"""The vault: issue, resolve, collisions, tombstones, occupancy and keys (design §4.3, §6)."""

import base64
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from airtimesat_platform.common.secrets import SecretValue
from airtimesat_platform.masker.detect.canary import canary
from airtimesat_platform.masker.errors import MaskingError, VaultError
from airtimesat_platform.masker.keys import Key, MaskingKeys, decode_key
from airtimesat_platform.masker.tokenize import vault as vault_module
from airtimesat_platform.masker.tokenize.surrogates import SPECS, derive
from airtimesat_platform.masker.tokenize.vault import InMemoryVaultStore, Vault

KeysFactory = Callable[[int], MaskingKeys]
# "CANARY" in full-width letters.
FULL_WIDTH_CANARY = "".join(chr(ord(c) + 0xFEE0) for c in "CANARY")


def test_issue_and_resolve_round_trip(vault: Vault) -> None:
    real = canary("IMEI", 1)
    surrogate = vault.issue("IMEI", real)
    assert SPECS["IMEI"].is_surrogate_shape(surrogate)
    assert vault.resolve("IMEI", surrogate) == real
    assert vault.issued["IMEI"] == 1


def test_consistency_across_runs_with_the_same_store_and_key(
    store: InMemoryVaultStore, keys_factory: KeysFactory
) -> None:
    real = canary("CONTRACT", 4)
    first = Vault(store, keys_factory(1)).issue("CONTRACT", real)
    second = Vault(store, keys_factory(1)).issue("CONTRACT", real)
    assert first == second
    assert len(store.rows) == 1


def test_a_different_k_mask_gives_a_different_surrogate(keys_factory: KeysFactory) -> None:
    real = canary("IMEI", 2)
    a = Vault(InMemoryVaultStore(), keys_factory(1)).issue("IMEI", real)
    b = Vault(InMemoryVaultStore(), keys_factory(7)).issue("IMEI", real)
    assert a != b


def test_unknown_surrogates_are_not_issued(vault: Vault) -> None:
    with pytest.raises(VaultError) as info:
        vault.resolve("IMEI", "990000000000000")
    assert info.value.code == "IDENTIFIER_NOT_ISSUED"
    with pytest.raises(VaultError):
        vault.resolve("NOT_A_TYPE", "x")


def test_tombstone_keeps_the_slot_and_resolves_to_nothing(
    store: InMemoryVaultStore, vault: Vault, keys_factory: KeysFactory
) -> None:
    real = canary("IMSI", 3)
    surrogate = vault.issue("IMSI", real)
    store.tombstone("IMSI", surrogate)
    with pytest.raises(VaultError):
        vault.resolve("IMSI", surrogate)
    # The same value seen again later never reuses the reserved slot.
    again = Vault(store, keys_factory(1)).issue("IMSI", real)
    assert again != surrogate
    assert store.rows[("IMSI", again)].counter == 1


def test_collisions_move_to_the_next_counter(
    vault: Vault, store: InMemoryVaultStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def colliding(key: bytes, type_name: str, real: str, counter: int) -> bytes:
        del real
        return derive(key, type_name, "same", counter)

    monkeypatch.setattr(vault_module, "derive", colliding)
    values = [canary("IMEI", n) for n in range(5)]
    surrogates = [vault.issue("IMEI", v) for v in values]
    assert len(set(surrogates)) == 5
    assert sorted(row.counter for row in store.rows.values()) == [0, 1, 2, 3, 4]
    for real, surrogate in zip(values, surrogates, strict=True):
        assert vault.resolve("IMEI", surrogate) == real


def test_collision_limit(vault: Vault, monkeypatch: pytest.MonkeyPatch) -> None:
    def constant(key: bytes, type_name: str, real: str, counter: int) -> bytes:
        del real, counter
        return derive(key, type_name, "same", 0)

    monkeypatch.setattr(vault_module, "derive", constant)
    vault.issue("IMEI", canary("IMEI", 1))
    with pytest.raises(VaultError) as info:
        vault.issue("IMEI", canary("IMEI", 2))
    assert info.value.code == "COLLISION_LIMIT"


class _FullStore(InMemoryVaultStore):
    def count(self, type_name: str) -> int:
        del type_name
        return 5000


def test_occupancy_cap_stops_issuing(keys_factory: KeysFactory) -> None:
    # IMO surrogates have 10^4 slots; the cap is 50% (design §4.3).
    vault = Vault(_FullStore(), keys_factory(1))
    with pytest.raises(VaultError) as info:
        vault.issue("IMO", canary("IMO", 1))
    assert info.value.code == "SURROGATE_SPACE_EXHAUSTED"
    assert vault.issue("IMEI", canary("IMEI", 1))


def test_real_values_in_a_reserved_prefix_are_refused_and_counted(vault: Vault) -> None:
    with pytest.raises(VaultError) as info:
        vault.issue("IMEI", "99" + "0" * 13)
    assert info.value.code == "REAL_VALUE_IN_RESERVED_PREFIX"
    assert vault.in_prefix["IMEI"] == 1
    assert "99" not in str(info.value)


def test_canary_range_is_counted_not_refused(vault: Vault) -> None:
    vault.issue("IMEI", canary("IMEI", 5))
    vault.issue("EMAIL", canary("EMAIL", 5))
    assert vault.in_canary_range["IMEI"] == 1
    assert vault.in_canary_range["EMAIL"] == 1


def test_values_are_encrypted_with_their_slot_as_associated_data(
    vault: Vault, store: InMemoryVaultStore
) -> None:
    a = vault.issue("IMEI", canary("IMEI", 1))
    b = vault.issue("IMEI", canary("IMEI", 2))
    row_a, row_b = store.rows[("IMEI", a)], store.rows[("IMEI", b)]
    assert row_a.ciphertext is not None
    assert canary("IMEI", 1).encode() not in row_a.ciphertext
    # A ciphertext moved to another slot does not decrypt.
    store.rows[("IMEI", b)] = replace(row_b, ciphertext=row_a.ciphertext)
    with pytest.raises(VaultError) as info:
        vault.resolve("IMEI", b)
    assert info.value.code == "VAULT_INTEGRITY"


def test_store_refuses_a_taken_slot(store: InMemoryVaultStore, vault: Vault) -> None:
    surrogate = vault.issue("IMEI", canary("IMEI", 1))
    with pytest.raises(VaultError):
        store.insert(store.rows[("IMEI", surrogate)])


def test_last_seen_is_updated(store: InMemoryVaultStore, keys_factory: KeysFactory) -> None:
    times = iter([datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=d) for d in range(10)])
    vault = Vault(store, keys_factory(1), clock=lambda: next(times))
    surrogate = vault.issue("IMEI", canary("IMEI", 1))
    vault.resolve("IMEI", surrogate)
    row = store.rows[("IMEI", surrogate)]
    assert row.last_seen > row.first_seen


def test_known_values_are_keyed_hashes(vault: Vault, store: InMemoryVaultStore) -> None:
    vault.add_known("Canary  Vessel One")
    vault.add_known("abc")
    assert vault.is_known("canary vessel one")
    assert vault.is_known(FULL_WIDTH_CANARY + " Vessel One")
    assert not vault.is_known("abc")
    assert all(b"Canary" not in digest for digest in store.known)


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=40)
@given(values=st.lists(st.text(min_size=1, max_size=12), min_size=1, max_size=20, unique=True))
def test_distinct_values_get_distinct_surrogates(
    values: list[str], keys_factory: KeysFactory
) -> None:
    vault = Vault(InMemoryVaultStore(), keys_factory(1))
    issued: dict[str, str] = {}
    for value in values:
        if SPECS["NAME"].in_reserved_space(value):
            continue
        issued[value] = vault.issue("NAME", value)
    assert len(set(issued.values())) == len(issued)
    for value, surrogate in issued.items():
        assert vault.resolve("NAME", surrogate) == value


def test_decode_key_accepts_hex_and_base64() -> None:
    hex_key = decode_key(SecretValue("ab" * 32))
    assert hex_key.material() == bytes([0xAB]) * 32
    b64 = decode_key(SecretValue(base64.b64encode(bytes(32)).decode()))
    assert b64.material() == bytes(32)


@pytest.mark.parametrize("text", ["", "abcd", "zz" * 32, "AAAA", "not base64!"])
def test_decode_key_refuses_bad_material(text: str) -> None:
    with pytest.raises(MaskingError) as info:
        decode_key(SecretValue(text))
    assert info.value.code == "KEY_INVALID"
    if text:
        assert text not in str(info.value)


def test_keys_do_not_print_and_are_not_reused() -> None:
    key = Key(bytes(32))
    assert "00" not in repr(key)
    assert str(key) == "**********"
    assert key == Key(bytes(32))
    assert hash(key) == hash(Key(bytes([1]) * 32))
    assert key != "not a key"
    with pytest.raises(MaskingError) as info:
        MaskingKeys(key, Key(bytes(32)), Key(bytes([1]) * 32))
    assert info.value.code == "KEY_REUSED"
    keys = MaskingKeys(Key(bytes(32)), Key(bytes([1]) * 32), Key(bytes([2]) * 32))
    assert "00" not in repr(keys)
