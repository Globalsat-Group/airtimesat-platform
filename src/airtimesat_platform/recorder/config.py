"""The recorder's configuration: one small TOML file on the trusted machine (design §6.1, §6.3).

``~/.config/airtimesat/recorder.toml``, or the file named by ``--config``. It holds four
paths and a public key, never a secret:

- ``data_dir``: the folder of the vault and run log, outside every git working tree;
- ``checkout``: the trusted git checkout of this repository;
- ``backup_recipient``: the age public key (``age1...``) that vault backups are encrypted to;
- ``backup_dir``: where ``recorder backup`` writes its files, outside the checkout.

Unknown keys are refused, so a misspelled key cannot be silently ignored.
"""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from airtimesat_platform.recorder.errors import RecorderError

DEFAULT_PATH: Final = Path("~/.config/airtimesat/recorder.toml")
KEYS: Final = frozenset({"data_dir", "checkout", "backup_recipient", "backup_dir"})
# An age X25519 recipient: "age1" and 58 Bech32 characters.
AGE_RECIPIENT: Final = re.compile(r"age1[02-9ac-hj-np-z]{58}")


@dataclass(frozen=True, slots=True)
class Config:
    """The validated configuration."""

    data_dir: Path
    checkout: Path
    backup_recipient: str
    backup_dir: Path


def _path(data: dict[str, object], key: str) -> Path:
    value = data[key]
    if not isinstance(value, str) or not value:
        raise RecorderError("CONFIG_WRONG_TYPE", key)
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise RecorderError("CONFIG_PATH_NOT_ABSOLUTE", key)
    return path.resolve()


def load_config(path: Path | None = None) -> Config:
    """Read and check the configuration file; refuse it with a code and the key at fault."""
    file = (path or DEFAULT_PATH).expanduser()
    try:
        data = tomllib.loads(file.read_text(encoding="utf-8"))
    except OSError:
        raise RecorderError("CONFIG_UNREADABLE") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise RecorderError("CONFIG_INVALID") from None
    unknown = set(data) - KEYS
    if unknown:
        # Show a key only if it is one of ours: an unknown key is text from the file.
        raise RecorderError("CONFIG_UNKNOWN_KEY")
    missing = sorted(KEYS - set(data))
    if missing:
        raise RecorderError("CONFIG_MISSING_KEY", missing[0])
    recipient = data["backup_recipient"]
    if not isinstance(recipient, str) or not AGE_RECIPIENT.fullmatch(recipient):
        raise RecorderError("CONFIG_INVALID_RECIPIENT", "backup_recipient")
    config = Config(
        data_dir=_path(data, "data_dir"),
        checkout=_path(data, "checkout"),
        backup_recipient=recipient,
        backup_dir=_path(data, "backup_dir"),
    )
    for key, folder in (("data_dir", config.data_dir), ("backup_dir", config.backup_dir)):
        if folder.is_relative_to(config.checkout):
            raise RecorderError("CONFIG_PATH_IN_CHECKOUT", key)
    return config
