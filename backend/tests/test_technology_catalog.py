"""The catalog is edited by hand, so its invariants are enforced by tests.

A vendor table is the kind of file people paste into. The failures that follow
are quiet ones: a term listed under two types resolves differently depending on
which pass reads it, a platform pointing at a type nothing produces never merges,
and an alias group naming an id no pass emits reports a duplicate that cannot
exist. Each of those produces an architecture model that looks right.
"""

import pytest

from app.engine import technology_catalog as catalog
from app.engine.nlp_processor import TECH_COMPONENT_MAP, NLPProcessor


def test_the_catalog_loads_and_is_not_nearly_empty():
    """A parse that silently yields a handful of terms would still 'work'."""
    assert len(catalog.TECHNOLOGY_TYPES) > 150
    assert catalog.VERSION.startswith("technology-catalog-")


def test_every_term_resolves_to_exactly_one_type():
    # _technologies raises on a conflict, so reaching here means the file is
    # unambiguous; this asserts the loader is actually the one enforcing it.
    for term, component_type in catalog.TECHNOLOGY_TYPES.items():
        assert term == term.lower().strip(), f"'{term}' is not normalized"
        assert component_type, f"'{term}' has no type"


def test_a_conflicting_term_is_rejected_rather_than_resolved_arbitrarily():
    document = {
        "technologies": {
            "Database": ["redis"],
            "Queue": ["redis"],
        }
    }
    with pytest.raises(catalog.CatalogError, match="redis"):
        catalog._technologies(document, catalog.CATALOG_PATH)


def test_the_most_specific_spelling_wins_regardless_of_file_order():
    """The tables this replaced matched in insertion order, which was luck."""
    assert catalog.classify("we call azure openai for completions") == "ML Service"
    assert catalog.classify("an aws api gateway fronts the service") == "API Gateway"
    assert catalog.classify("a vector store holds the embeddings") == "Database"


def test_a_component_is_classified_by_its_head_noun_not_by_where_it_is_hosted():
    """Two technologies in one phrase; only the first one is the component."""
    assert catalog.classify("React SPA hosted on CloudFront") == "WebClient"
    assert catalog.classify("a Postgres database behind an ALB") == "Database"
    assert catalog.classify("CloudFront in front of the React SPA") == "CDN"


def test_terms_are_matched_as_words_not_as_substrings():
    assert catalog.mentions("data lands in s3", "s3")
    assert not catalog.mentions("the s3cret is rotated", "s3")
    # "gin" inside "logging" was a real false positive before boundaries.
    assert not catalog.mentions("logging is enabled", "gin")
    assert catalog.mentions("the api runs on node.js", "node.js")


def test_longest_first_ordering_is_strictly_descending():
    lengths = [len(term) for term in catalog.terms_longest_first()]
    assert lengths == sorted(lengths, reverse=True)
    assert len(catalog.terms_longest_first()) == len(catalog.TECHNOLOGY_TYPES)


def test_every_platform_is_also_a_known_technology():
    """A platform the extractor never produces can never be merged away."""
    unknown = [
        platform for platform in catalog.PLATFORM_TECHNOLOGIES
        if platform not in catalog.TECHNOLOGY_TYPES
    ]
    assert unknown == ["swift", "kotlin"], (
        "swift and kotlin are known exceptions: they are merge targets only. "
        f"New unlisted platforms: {unknown}"
    )


def test_every_platform_declares_at_least_one_host_type():
    for platform, hosts in catalog.PLATFORM_TECHNOLOGIES.items():
        assert hosts, f"{platform} hosts nothing, so it can never merge"


def test_display_names_respell_a_platform_rather_than_rename_it():
    """"nextjs" may display as "Next.js"; it may not display as "React"."""
    letters = lambda value: "".join(character for character in value.lower() if character.isalnum())
    for platform, display in catalog.PLATFORM_DISPLAY_NAMES.items():
        assert letters(display) == letters(platform), (
            f"{platform} displays as {display}, which is a different name, not a spelling"
        )


def test_equivalent_types_only_reference_types_the_catalog_produces():
    for term, types in catalog.EQUIVALENT_TYPES.items():
        assert term in catalog.TECHNOLOGY_TYPES, f"'{term}' is not a catalogued technology"
        unknown = types - catalog.COMPONENT_TYPES
        assert not unknown, f"'{term}' claims to be covered by unknown type(s) {unknown}"


def test_a_term_is_covered_by_its_equivalent_type_and_not_by_others():
    assert catalog.covered_by("rest api", frozenset({"API"}))
    assert not catalog.covered_by("rest api", frozenset({"Database"}))
    # A term with no equivalence is only satisfied by being named outright.
    assert not catalog.covered_by("postgresql", frozenset({"Database"}))


def test_logical_terms_are_not_also_catalogued_technologies():
    """A term in both would be extracted as a component and reported as missing."""
    overlap = set(catalog.LOGICAL_TERMS) & set(catalog.TECHNOLOGY_TYPES)
    assert not overlap, f"listed as both a technology and a logical term: {overlap}"


def test_alias_groups_name_at_least_two_ids_each():
    for group in catalog.ALIAS_GROUPS:
        assert len(group) >= 2, f"an alias group of one describes no duplicate: {group}"


def test_classifying_suffixes_are_suffixes():
    for suffix in catalog.CLASSIFYING_SUFFIXES:
        assert suffix.startswith("_"), f"'{suffix}' would match inside a word"


def test_the_extractor_reads_the_same_catalog():
    """One vendor table, not two that drift."""
    assert TECH_COMPONENT_MAP is catalog.TECHNOLOGY_TYPES


@pytest.mark.parametrize(
    "phrase,expected",
    [
        ("the PostgreSQL cluster", "Database"),
        ("an S3 bucket", "Object Storage"),
        ("the Kafka topic", "Queue"),
        ("Auth0 issues tokens", "Identity Provider"),
        ("a React single page app", "WebClient"),
        ("AWS KMS holds the keys", "Key Management"),
    ],
)
def test_classification_matches_what_a_reviewer_would_say(phrase, expected):
    assert NLPProcessor().classify_component_type(phrase) == expected
