"""Map a line of the merged analysis text back to the document that stated it.

Uploaded documents are concatenated into one description before parsing, so by
the time a component is extracted the text no longer records which file, page or
table asserted it. Every finding then cites whichever document happened to be
uploaded first, which is wrong as soon as there are two.

The mapping is rebuilt from the headers ingestion already writes rather than
threading offsets through the callers that reshape the description. Those callers
filter sections and prepend context, so an offset computed at extraction time
does not survive; the assembled text is the only thing that is still true.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# What a fact is attributed to when the description was typed rather than
# uploaded. The plain /analyze path has no documents at all and still deserves a
# citation, so it gets a source like any other.
NARRATIVE_SOURCE_ID = "narrative"
NARRATIVE_DOCUMENT = "architecture input"

# A header line describes the document rather than the architecture. Anything
# attributed here was matched against a filename or a role label, which is worth
# seeing plainly instead of being reported as a line of the design.
HEADER_LOCATOR = "document header"

_CONTEXT_HEADER = re.compile(r"^User Context:\s*$")
_DOCUMENT_HEADER = re.compile(r"^Document:\s*(?P<name>\S.*?)\s*$")
_TYPE_HEADER = re.compile(r"^Type:\s*(?P<value>\S.*?)\s*$")
_ROLE_HEADER = re.compile(r"^Role:\s*(?P<value>\S.*?)\s*$")
_CONTENT_HEADER = re.compile(r"^Content:\s*$")
_SEPARATOR = re.compile(r"^-{3,}\s*$")
_PAGE_MARK = re.compile(r"^\[Page\s+(?P<number>\d+)\]\s*$", re.IGNORECASE)
_TABLE_MARK = re.compile(r"^\[Table\s+(?P<number>\d+)\]\s*$", re.IGNORECASE)

# Type and Role only follow a Document line. Bounding the run stops a design that
# happens to contain a line like "Role: operator" from being read as metadata.
_HEADER_RUN = 3


@dataclass(frozen=True)
class Citation:
    """Where one statement came from, in terms a reader can go and check."""

    source_id: str
    document: str
    role: str = "source_design"
    locator: Optional[str] = None
    line: Optional[int] = None

    def display(self) -> str:
        parts = [self.document]
        if self.locator:
            parts.append(self.locator)
        if self.line:
            parts.append(f"line {self.line}")
        return ", ".join(parts)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "document": self.document,
            "role": self.role,
            "locator": self.locator,
            "line": self.line,
            "cite": self.display(),
        }


class SourceIndex:
    """Resolves 1-based line numbers of the merged text to citations."""

    def __init__(self, citations: List[Citation], sources: List[Dict[str, Any]], lines: List[str]):
        self._citations = citations
        self._sources = sources
        self._lines = lines

    @property
    def sources(self) -> List[Dict[str, Any]]:
        """One record per source, in the order they appear in the text."""
        return [dict(record) for record in self._sources]

    @property
    def multi_source(self) -> bool:
        return len(self._sources) > 1

    def cite(self, line: Optional[int]) -> Optional[Citation]:
        if not line or line < 1 or line > len(self._citations):
            return None
        return self._citations[line - 1]

    def find(self, fragment: str) -> Optional[Citation]:
        """Cite the first line containing `fragment`.

        For callers holding a statement but no line number, which is most of
        them: the parser records the sentence it matched, not where it sat.
        """
        needle = " ".join((fragment or "").split()).lower()
        if not needle:
            return None
        for index, citation in enumerate(self._citations):
            if citation.line is None:
                continue
            if needle in " ".join(self._lines[index].split()).lower():
                return citation
        return None


def build(text: str) -> SourceIndex:
    """Index the assembled description by the structure ingestion wrote into it."""
    lines = (text or "").splitlines()
    citations: List[Optional[Citation]] = []
    sources: List[Dict[str, Any]] = []
    documents_seen = 0

    current: Optional[Dict[str, Any]] = None
    locator: Optional[str] = None
    body_line = 0
    header_run = 0

    def open_source(source_id: str, document: str, role: str, kind: str) -> Dict[str, Any]:
        record = {
            "source_id": source_id,
            "document": document,
            "role": role,
            "type": kind,
            "lines": 0,
        }
        sources.append(record)
        return record

    def at_header(source: Dict[str, Any]) -> Citation:
        return Citation(source["source_id"], source["document"], source["role"], HEADER_LOCATOR)

    for raw in lines:
        stripped = raw.strip()

        if _SEPARATOR.match(stripped):
            # A separator carries no statement, so it gets no line number. It
            # does not close the current source either: a document body may
            # contain a horizontal rule, and closing on one would attribute the
            # rest of that file to nothing. Only a header opens a new source.
            citations.append(Citation(current["source_id"], current["document"], current["role"]) if current else None)
            header_run = 0
            continue

        if _CONTEXT_HEADER.match(stripped):
            current = open_source(NARRATIVE_SOURCE_ID, NARRATIVE_DOCUMENT, "user_context", "text")
            locator, body_line, header_run = None, 0, 0
            citations.append(at_header(current))
            continue

        document_match = _DOCUMENT_HEADER.match(stripped)
        if document_match:
            documents_seen += 1
            current = open_source(
                f"doc{documents_seen}", document_match.group("name"), "source_design", "document",
            )
            locator, body_line, header_run = None, 0, _HEADER_RUN
            citations.append(at_header(current))
            continue

        if current is not None and header_run:
            header_run -= 1
            type_match = _TYPE_HEADER.match(stripped)
            role_match = _ROLE_HEADER.match(stripped)
            content_match = _CONTENT_HEADER.match(stripped)
            if type_match:
                current["type"] = type_match.group("value")
            elif role_match:
                current["role"] = role_match.group("value")
            elif content_match:
                header_run = 0
            if type_match or role_match or content_match:
                citations.append(at_header(current))
                continue

        if current is None:
            # Text before any header is the description as typed. The plain
            # /analyze path is entirely this case.
            current = open_source(NARRATIVE_SOURCE_ID, NARRATIVE_DOCUMENT, "user_context", "text")
            locator, body_line = None, 0

        page = _PAGE_MARK.match(stripped)
        table = _TABLE_MARK.match(stripped)
        if page or table:
            mark = page or table
            locator = f"{'page' if page else 'table'} {mark.group('number')}"
            citations.append(Citation(current["source_id"], current["document"], current["role"], locator))
            continue

        body_line += 1
        current["lines"] = body_line
        citations.append(
            Citation(current["source_id"], current["document"], current["role"], locator, body_line)
        )

    unattributed = Citation(NARRATIVE_SOURCE_ID, NARRATIVE_DOCUMENT, "user_context")
    return SourceIndex([item or unattributed for item in citations], sources, lines)
