"""A strict YAML loader for reviewed files (design §5.2).

No duplicate keys, anchors, aliases, merge keys or explicit tags. A reviewer reads the
raw text and the program uses what this loader parses, so the two cannot differ. The
recorder's plan loader can reuse it.
"""

from typing import Any, Final, cast

import yaml
import yaml.events
from yaml.nodes import MappingNode, Node

from airtimesat_platform.masker.errors import FieldMapError

MAX_BYTES: Final = 2 * 1024 * 1024


class StrictYamlError(FieldMapError):
    """The document breaks a strict-YAML rule. Carries a code and a line, never content."""


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses aliases, anchors, explicit tags, merge keys and duplicates."""

    def compose_node(self, parent: Node | None, index: object) -> Node | None:
        event = cast(yaml.events.Event, self.peek_event())  # pyright: ignore[reportUnknownMemberType]
        line = str(event.start_mark.line + 1) if event.start_mark else "?"
        if isinstance(event, yaml.AliasEvent):
            raise StrictYamlError("YAML_ALIAS", path=f"line {line}")
        anchor = getattr(event, "anchor", None)
        if anchor is not None:
            raise StrictYamlError("YAML_ANCHOR", path=f"line {line}")
        tag = getattr(event, "tag", None)
        if tag is not None and tag != "!":
            raise StrictYamlError("YAML_TAG", path=f"line {line}")
        return super().compose_node(parent, index)  # type: ignore[arg-type]

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[object] = set()
        for key_node, _ in node.value:
            line = str(key_node.start_mark.line + 1)
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise StrictYamlError("YAML_MERGE_KEY", path=f"line {line}")
            key = self.construct_object(key_node, deep=True)  # type: ignore[no-untyped-call]
            if not isinstance(key, str):
                raise StrictYamlError("YAML_NON_STRING_KEY", path=f"line {line}")
            if key in seen:
                raise StrictYamlError("YAML_DUPLICATE_KEY", path=f"line {line}")
            seen.add(key)
        return cast(dict[Any, Any], super().construct_mapping(node, deep=True))


def load_strict(text: str) -> object:
    """Parse one strict YAML document."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise StrictYamlError("YAML_TOO_LARGE")
    try:
        return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - a SafeLoader subclass
    except StrictYamlError:
        raise
    except yaml.YAMLError:
        raise StrictYamlError("YAML_SYNTAX") from None
