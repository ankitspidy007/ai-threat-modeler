"""Load the technology catalog and expose it to the passes that need it.

The catalog is data (app/data/technology_catalog.yaml) rather than three tables
in three modules, so a vendor is taught to the tool once. This module is the
only reader: it validates the file on import and fails loudly, because a catalog
that silently loses half its entries produces an architecture model that looks
plausible and is wrong.

Matching is longest-term-first everywhere. The previous tables were dictionaries
matched in insertion order, which meant "azure openai" resolved correctly only
because of where someone happened to type it.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

import yaml

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "technology_catalog.yaml"


class CatalogError(RuntimeError):
    """The catalog is missing or malformed."""


def _load(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise CatalogError(f"Technology catalog not found at {path}") from exc
    except yaml.YAMLError as exc:
        raise CatalogError(f"Technology catalog at {path} is not valid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise CatalogError(f"Technology catalog at {path} must be a mapping")
    return document


def _technologies(document: Dict[str, Any], path: Path) -> Dict[str, str]:
    """Invert the type-grouped listing into term -> type."""
    grouped = document.get("technologies") or {}
    if not isinstance(grouped, dict) or not grouped:
        raise CatalogError(f"Technology catalog at {path} lists no technologies")

    resolved: Dict[str, str] = {}
    for component_type, terms in grouped.items():
        if not isinstance(terms, list):
            raise CatalogError(f"technologies.{component_type} must be a list of terms")
        for term in terms:
            term = str(term).strip().lower()
            if not term:
                continue
            # A term under two types would resolve differently depending on the
            # reader, which is exactly the ambiguity this file exists to remove.
            if term in resolved and resolved[term] != component_type:
                raise CatalogError(
                    f"'{term}' is listed under both {resolved[term]} and {component_type}"
                )
            resolved[term] = str(component_type)
    return resolved


def _platforms(document: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    platforms: Dict[str, Dict[str, Any]] = {}
    for name, entry in (document.get("platforms") or {}).items():
        if not isinstance(entry, dict) or not entry.get("hosts"):
            raise CatalogError(f"platforms.{name} must define the component types it hosts")
        platforms[str(name).lower()] = {
            "hosts": tuple(str(host) for host in entry["hosts"]),
            "display": str(entry["display"]) if entry.get("display") else None,
        }
    return platforms


def _string_map(document: Dict[str, Any], key: str) -> Dict[str, str]:
    return {
        str(term).lower(): str(value)
        for term, value in (document.get(key) or {}).items()
    }


def _type_sets(document: Dict[str, Any], key: str) -> Dict[str, FrozenSet[str]]:
    return {
        str(term).lower(): frozenset(str(value) for value in values)
        for term, values in (document.get(key) or {}).items()
    }


_DOCUMENT = _load(CATALOG_PATH)

VERSION: str = str(_DOCUMENT.get("version") or "unversioned")

#: Every recognized technology term mapped to its architectural type.
TECHNOLOGY_TYPES: Dict[str, str] = _technologies(_DOCUMENT, CATALOG_PATH)

#: The component types the catalog uses, which is the vocabulary the rest of the
#: engine is allowed to assume exists.
COMPONENT_TYPES: FrozenSet[str] = frozenset(TECHNOLOGY_TYPES.values())

PLATFORMS: Dict[str, Dict[str, Any]] = _platforms(_DOCUMENT)

#: platform -> the component types it can describe.
PLATFORM_TECHNOLOGIES: Dict[str, Tuple[str, ...]] = {
    name: entry["hosts"] for name, entry in PLATFORMS.items()
}

#: platform -> its accepted spelling, for platforms that are not title case.
PLATFORM_DISPLAY_NAMES: Dict[str, str] = {
    name: entry["display"] for name, entry in PLATFORMS.items() if entry["display"]
}

EQUIVALENT_TYPES: Dict[str, FrozenSet[str]] = _type_sets(_DOCUMENT, "equivalent_types")

LOGICAL_TERMS: Dict[str, str] = _string_map(_DOCUMENT, "logical_terms")

ALIAS_GROUPS: Tuple[FrozenSet[str], ...] = tuple(
    frozenset(str(alias) for alias in group) for group in (_DOCUMENT.get("alias_groups") or [])
)

CLASSIFYING_SUFFIXES: Tuple[str, ...] = tuple(
    str(suffix) for suffix in (_DOCUMENT.get("classifying_suffixes") or [])
)

#: Vendor-neutral role phrases mapped to the type they describe.
ROLE_TERMS: Dict[str, str] = _string_map(_DOCUMENT, "role_terms")


def _role_vocabulary(path: Path) -> Dict[str, str]:
    """Vendors, logical terms and role phrases in one term -> type mapping.

    A term that means two things depending on which section a reader consults is
    the ambiguity this catalog exists to remove, so an overlap is a load error
    rather than a silent precedence rule.
    """
    vocabulary: Dict[str, str] = dict(TECHNOLOGY_TYPES)
    for source, mapping in (("logical_terms", LOGICAL_TERMS), ("role_terms", ROLE_TERMS)):
        for term, component_type in mapping.items():
            existing = vocabulary.get(term)
            if existing is not None and existing != component_type:
                raise CatalogError(
                    f"'{term}' in {source} is {component_type} but is already {existing} "
                    f"elsewhere in {path.name}"
                )
            vocabulary[term] = component_type
    unknown = {
        component_type for component_type in vocabulary.values()
        if component_type not in COMPONENT_TYPES
    }
    if unknown:
        raise CatalogError(
            f"role vocabulary in {path.name} uses types no technology declares: "
            f"{', '.join(sorted(unknown))}"
        )
    return vocabulary


#: Every phrase that can type a component, by vendor name or by job.
ROLE_VOCABULARY: Dict[str, str] = _role_vocabulary(CATALOG_PATH)


def names_one_thing(*words: str) -> bool:
    """Whether these adjacent words are a single name rather than a sequence.

    "Spring" followed by "Boot" is one framework, so a rule that shortens a
    phrase must not cut between them: the remainder would be "Boot", which names
    nothing anyone wrote down.
    """
    phrase = " ".join(word.strip().lower() for word in words if word and word.strip())
    return bool(phrase) and (phrase in ROLE_VOCABULARY or phrase in PLATFORM_TECHNOLOGIES)


def _control_domains(document: Dict[str, Any], path: Path) -> Dict[str, Dict[str, Any]]:
    domains: Dict[str, Dict[str, Any]] = {}
    for name, entry in (document.get("control_domains") or {}).items():
        if not isinstance(entry, dict) or not entry.get("asserts"):
            raise CatalogError(f"control_domains.{name} must declare what it asserts")
        types = tuple(str(value) for value in entry.get("types") or ())
        terms = tuple(str(value).lower() for value in entry.get("terms") or ())
        if not types and not terms:
            raise CatalogError(
                f"control_domains.{name} must target component types or terms, "
                "otherwise the row credits nothing"
            )
        unknown = [value for value in types if value not in COMPONENT_TYPES]
        if unknown:
            raise CatalogError(
                f"control_domains.{name} targets unknown types: {', '.join(unknown)}"
            )
        type_asserts = entry.get("type_asserts") or {}
        unknown_scoped = [value for value in type_asserts if value not in COMPONENT_TYPES]
        if unknown_scoped:
            raise CatalogError(
                f"control_domains.{name}.type_asserts targets unknown types: "
                f"{', '.join(unknown_scoped)}"
            )
        domains[str(name).lower()] = {
            "types": frozenset(types),
            "terms": terms,
            "exposed": bool(entry.get("exposed")),
            "asserts": dict(entry["asserts"]),
            "type_asserts": {
                str(key): dict(value) for key, value in type_asserts.items()
            },
        }
    if not domains:
        raise CatalogError(f"Technology catalog at {path} declares no control domains")
    return domains


#: Control-table domain -> the components it credits and the properties it sets.
CONTROL_DOMAINS: Dict[str, Dict[str, Any]] = _control_domains(_DOCUMENT, CATALOG_PATH)


def terms_longest_first() -> List[str]:
    """Every technology term, most specific first.

    Substring and word-boundary matching both have to try "azure openai" before
    "openai", or the more specific term is never reachable.
    """
    return _terms_longest_first()


@lru_cache(maxsize=1)
def _terms_longest_first() -> Tuple[str, ...]:
    return tuple(sorted(TECHNOLOGY_TYPES, key=lambda term: (-len(term), term)))


@lru_cache(maxsize=4096)
def _word_boundary_pattern(term: str) -> "re.Pattern[str]":
    # Guarded by character classes rather than \b because terms contain dots and
    # digits: \b would match "s3" inside "s3cret" and miss "node.js" entirely.
    return re.compile(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])")


def mentions(text: str, term: str) -> bool:
    """Whether the text uses this exact term, not merely the characters in it."""
    return first_mention(text, term) is not None


def first_mention(text: str, term: str) -> Optional[int]:
    """Where the text first uses this exact term, or None if it does not."""
    match = _word_boundary_pattern(term).search((text or "").lower())
    return match.start() if match else None


def classify(text: str) -> Optional[str]:
    """The architectural type of the component this text describes.

    A description often names more than one technology, and only one of them is
    the component: "a React SPA hosted on CloudFront" is a web client that
    happens to sit behind a CDN. English puts the head of the phrase first, so
    the earliest term wins, and the longest term wins at the same position so
    that "Azure OpenAI" is not read as "OpenAI".
    """
    return _classify_with(text, TECHNOLOGY_TYPES)


def _classify_with(text: str, vocabulary: Dict[str, str]) -> Optional[str]:
    lowered = (text or "").lower()
    best: Optional[Tuple[int, int, str]] = None
    for term in vocabulary:
        match = _word_boundary_pattern(term).search(lowered)
        if match is None:
            continue
        candidate = (match.start(), -len(term), term)
        if best is None or candidate < best:
            best = candidate
    return vocabulary[best[2]] if best else None


def classify_role(text: str) -> Optional[str]:
    """The type of the component this text names, by vendor or by job.

    `classify` answers "which technology is this", which is the right question
    for prose that mentions technologies in passing. This answers "what is this
    component", which is the right question for a row in an architecture table:
    the row already asserts a component exists, and "Clinical document store"
    has to resolve even though it names no product.
    """
    return _classify_with(text, ROLE_VOCABULARY)


def covered_by(term: str, represented_types: FrozenSet[str]) -> bool:
    """Whether a component of one of these types already represents the term."""
    return bool(represented_types & EQUIVALENT_TYPES.get(term, frozenset()))
