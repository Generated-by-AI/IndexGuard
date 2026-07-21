"""Deterministic text-unit diffing for normalized document snapshots.

This module deliberately reports structural evidence only. It does not assign a
risk score or make an ALLOW/REVIEW/BLOCK decision.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher

from indexguard.contracts import (
    ChangeKind,
    DiffReport,
    DocumentChange,
    DocumentSnapshot,
    NumericChange,
    TextLocation,
)

NORMALIZATION_VERSION = "nfc-whitespace-visible-controls-v1"

_EXPLICIT_ZERO_WIDTH_CODEPOINTS = frozenset(
    {
        0x034F,  # COMBINING GRAPHEME JOINER
        0x180E,  # MONGOLIAN VOWEL SEPARATOR (historically zero-width)
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
    }
)
_BIDI_CONTROL_CLASSES = frozenset(
    {"BN", "FSI", "LRE", "LRI", "LRO", "PDF", "PDI", "RLE", "RLI", "RLO"}
)
_VISIBLE_CONTROL_RE = re.compile(r"⟦U\+[0-9A-F]{4,6}:[A-Z0-9_]+⟧")

_NUMERIC_UNIT = r"""
    (?:
        bps?|[%％]|퍼센트|
        [십백천만억조경]+\s*원|[십백천만억조경]+|
        원|달러|유로|엔|USD|KRW|EUR|JPY|
        년|개월|월|주|일|시간|분|초|
        명|개|건|회|배|곳|차|단계|등급|점|세|호|층|페이지|
        TB|GB|MB|KB|KiB|MiB|GiB
    )
"""
_NUMERIC_RE = re.compile(
    rf"""
    (?<![\w])
    (?:[₩$€¥]\s*)?
    (?:
        \d{{4}}[-/.]\d{{1,2}}[-/.]\d{{1,2}}
        |
        [+-−]?(?:\d{{1,3}}(?:[,_]\d{{3}})+|\d+)(?:\.\d+)?
    )
    (?:\s*{_NUMERIC_UNIT})?
    """,
    flags=re.IGNORECASE | re.VERBOSE,
)


@dataclass(frozen=True, slots=True)
class _NormalizedUnit:
    text: str
    location: TextLocation | None


def _is_invisible_control(character: str) -> bool:
    codepoint = ord(character)
    return (
        codepoint in _EXPLICIT_ZERO_WIDTH_CODEPOINTS
        or unicodedata.category(character) in {"Cc", "Cf"}
        or unicodedata.bidirectional(character) in _BIDI_CONTROL_CLASSES
    )


def _visible_control_token(character: str) -> str:
    name = unicodedata.name(character, "UNNAMED_CONTROL").replace("-", "_").replace(" ", "_")
    return f"⟦U+{ord(character):04X}:{name}⟧"


def normalize_text(text: str) -> str:
    """Return a stable NFC/whitespace-normalized representation of *text*.

    Ordinary whitespace collapses to one ASCII space. Invisible format, zero-
    width, bidi, and non-whitespace control characters become explicit tokens
    instead of being discarded, so an attacker cannot hide a diff in characters
    that the terminal or dashboard does not render.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")

    normalized = unicodedata.normalize("NFC", text)
    visible_parts: list[str] = []
    for character in normalized:
        if _is_invisible_control(character) and not character.isspace():
            visible_parts.extend((" ", _visible_control_token(character), " "))
        else:
            visible_parts.append(character)
    return " ".join("".join(visible_parts).split())


def extract_numeric_values(text: str | None) -> list[str]:
    """Extract ordered numeric/date/amount lexemes from normalized text.

    Visible control tokens include a Unicode code point (for example U+200B),
    so those evidence tokens are masked before extracting numbers.
    """

    if text is None:
        return []
    normalized = normalize_text(text)
    without_control_tokens = _VISIBLE_CONTROL_RE.sub(" ", normalized)
    return [match.group(0).strip() for match in _NUMERIC_RE.finditer(without_control_tokens)]


def _normalized_units(snapshot: DocumentSnapshot) -> list[_NormalizedUnit]:
    units = [
        _NormalizedUnit(text=normalized, location=unit.location)
        for unit in snapshot.units
        if (normalized := normalize_text(unit.text))
    ]
    if units:
        return units

    fallback_text = normalize_text(snapshot.text)
    if fallback_text:
        return [_NormalizedUnit(text=fallback_text, location=None)]
    return []


def _joined_text(units: list[_NormalizedUnit]) -> str | None:
    if not units:
        return None
    return " ".join(unit.text for unit in units)


def _locations(units: list[_NormalizedUnit]) -> list[TextLocation]:
    return [unit.location for unit in units if unit.location is not None]


def _changed_numeric_values(
    before_text: str | None, after_text: str | None
) -> tuple[list[str], list[str]]:
    before_values = extract_numeric_values(before_text)
    after_values = extract_numeric_values(after_text)
    matcher = SequenceMatcher(a=before_values, b=after_values, autojunk=False)

    changed_before: list[str] = []
    changed_after: list[str] = []
    for tag, before_start, before_end, after_start, after_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        changed_before.extend(before_values[before_start:before_end])
        changed_after.extend(after_values[after_start:after_end])
    return changed_before, changed_after


def diff_documents(
    baseline: DocumentSnapshot,
    candidate: DocumentSnapshot,
) -> DiffReport:
    """Build a deterministic unit-level diff and its numeric-change evidence."""

    before_units = _normalized_units(baseline)
    after_units = _normalized_units(candidate)
    matcher = SequenceMatcher(
        a=[unit.text for unit in before_units],
        b=[unit.text for unit in after_units],
        autojunk=False,
    )

    changes: list[DocumentChange] = []
    for tag, before_start, before_end, after_start, after_end in matcher.get_opcodes():
        if tag == "equal":
            continue

        before_slice = before_units[before_start:before_end]
        after_slice = after_units[after_start:after_end]
        if tag == "delete":
            kind = ChangeKind.DELETE
        elif tag == "insert":
            kind = ChangeKind.ADD
        else:
            kind = ChangeKind.REPLACE

        changes.append(
            DocumentChange(
                kind=kind,
                before=_joined_text(before_slice),
                after=_joined_text(after_slice),
                before_locations=_locations(before_slice),
                after_locations=_locations(after_slice),
            )
        )

    numeric_changes: list[NumericChange] = []
    for change_index, change in enumerate(changes):
        changed_before, changed_after = _changed_numeric_values(change.before, change.after)
        if changed_before or changed_after:
            numeric_changes.append(
                NumericChange(
                    before=changed_before,
                    after=changed_after,
                    change_index=change_index,
                )
            )

    return DiffReport(
        baseline_sha256=baseline.sha256,
        candidate_sha256=candidate.sha256,
        normalization_version=NORMALIZATION_VERSION,
        changes=changes,
        numeric_changes=numeric_changes,
    )


def build_document_diff(
    baseline: DocumentSnapshot,
    candidate: DocumentSnapshot,
) -> DiffReport:
    """Compatibility-friendly named entry point for :func:`diff_documents`."""

    return diff_documents(baseline, candidate)
