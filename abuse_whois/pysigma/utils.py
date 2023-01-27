import base64
from typing import Any

import regex as re

from . import schemas
from .exceptions import UnsupportedFeature

# TODO We need to support the rest of them
SUPPORTED_MODIFIERS = {
    "contains",
    "all",
    "base64",
    # 'base64offset'
    "endswith",
    "startswith",
    # 'utf16le',
    # 'utf16be',
    # 'wide',
    # 'utf16',
    # 're',
    # 'windash'
}


def decode_base64(x: str):
    x = x.replace("\n", "")
    return base64.b64encode(x.encode()).decode()


MODIFIER_FUNCTIONS = {
    "contains": lambda x: f".*{x}.*",
    "base64": lambda x: decode_base64(x),
    "endswith": lambda x: f".*{x}$",
    "startswith": lambda x: f"^{x}.*",
}


def process_field_name(field_string: str):
    name_and_modifiers = field_string.split("|")
    name = name_and_modifiers.pop(0)
    modifiers = [_m for _m in name_and_modifiers if _m]
    unsupported = set(modifiers) - SUPPORTED_MODIFIERS
    if unsupported:
        raise UnsupportedFeature(f"Unsupported field modifiers used: {unsupported}")

    return name, modifiers


_NSC = NON_SPECIAL_CHARACTERS = r"[^\\*?]*"
ESCAPED_SPECIAL_CHARACTER = r"(?:\\[*?])"
ESCAPED_OTHER_CHARACTER = r"(?:\\[^*?])"
ESCAPED_WILDCARD_PATTERN = re.compile(
    rf"(?:{_NSC}{ESCAPED_SPECIAL_CHARACTER}*{ESCAPED_OTHER_CHARACTER})*"
)

UPTO_WILDCARD = re.compile(r"^([^\\?*]+|(?:\\[^?*\\])+)+")


def sigma_string_to_regex(original_value: str):
    value = original_value
    full_content: list[str] = []

    while value:
        # Grab any content up to the first wildcard
        match = UPTO_WILDCARD.match(value)
        if match:
            # The non regex content in the sigma string, may have characters special to regex
            matched = match.group(0)
            full_content.append(re.escape(matched))
            value = value[len(matched) :]
        elif value.startswith("*"):
            full_content.append(".*")
            value = value[1:]
        elif value.startswith("\\*"):
            full_content.append(re.escape("*"))
            value = value[2:]
        elif value.startswith("?"):
            full_content.append(".")
            value = value[1:]
        elif value.startswith("\\?"):
            full_content.append(re.escape("?"))
            value = value[2:]
        elif value.startswith(r"\\*"):
            full_content.append(re.escape("\\") + ".*")
            value = value[3:]
        elif value.startswith(r"\\?"):
            full_content.append(re.escape("\\") + ".")
            value = value[3:]
        elif value.startswith("\\"):
            full_content.append(re.escape("\\"))
            value = value[1:]
        else:
            raise ValueError(
                f"Could not parse string matching pattern: {original_value}"
            )

    return "".join(full_content)  # Sigma strings are case insensitive


def get_modified_value(value: str, modifiers: list[str]) -> str:
    if modifiers:
        for mod in modifiers:
            func = MODIFIER_FUNCTIONS.get(mod)
            value = func(value) if func else value
    else:
        # If there are no modifiers, we assume exact match
        value = f"^{value}$"

    return value


def apply_modifiers(value: str, modifiers: list[str]) -> schemas.Query:
    """
    Apply as many modifiers as we can during signature construction
    to speed up the matching stage as much as possible.
    """
    # If there are wildcards, or we are using the regex modifier, compile the query
    # string to a regex pattern object
    if not ESCAPED_WILDCARD_PATTERN.fullmatch(value) or "re" in modifiers:
        # Transform the unescaped wildcards to their regex equivalent
        reg_value = sigma_string_to_regex(value)
        value = get_modified_value(reg_value, modifiers)
        return re.compile(value, flags=re.I | re.DOTALL | re.V1)

    value = get_modified_value(value, modifiers)
    # If we are just doing a full string compare of a raw string, the comparison
    # is case-insensitive in sigma, so all direct string comparisons will be lowercase.
    value = str(value).replace("\\*", "*").replace("\\?", "?")
    return value.lower()


def normalize_field_map(field: dict[str, Any]) -> schemas.DetectionMap:
    out: schemas.DetectionMap = []

    for raw_key, value in field.items():
        key, modifiers = process_field_name(raw_key)
        if value is None:
            out.append((key, ([None], modifiers)))
            continue

        if isinstance(value, list):
            out.append(
                (
                    key,
                    (
                        [
                            apply_modifiers(str(_v), modifiers)
                            if _v is not None
                            else None
                            for _v in value
                        ],
                        modifiers,
                    ),
                )
            )
            continue

        out.append((key, ([apply_modifiers(str(value), modifiers)], modifiers)))

    return out


def normalize_field_block(name: str, field: Any) -> schemas.DetectionField:
    if isinstance(field, dict):
        return schemas.DetectionField(map_search=[normalize_field_map(field)])

    if isinstance(field, list):
        if all(isinstance(_x, dict) for _x in field):
            return schemas.DetectionField(
                map_search=[normalize_field_map(_x) for _x in field]
            )

        return schemas.DetectionField(
            list_search=[apply_modifiers(str(_x), ["contains"]) for _x in field]
        )

    raise ValueError(f"Failed to parse selection field {name}: {field}")


def normalize_detection(detection: dict[str, Any]) -> dict[str, schemas.DetectionField]:
    return {name: normalize_field_block(name, data) for name, data in detection.items()}
