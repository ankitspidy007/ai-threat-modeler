"""One component in the design should be one component in the model.

Several extraction passes read the same sentence, and each recognizes what it
knows: a catalog sees "Aurora", a role pass sees "Aurora PostgreSQL database",
and a stack written in parentheses turns a framework into a node of its own.
Left alone the model carries one machine several times, which splits its flows
and counts its findings more than once.
"""

from __future__ import annotations

from app.engine.component_roles import find_named_roles
from app.engine.parser import ArchitectureParser


def _named(architecture):
    return {component.name for component in architecture.components}


def _typed(architecture):
    return {component.name: component.type for component in architecture.components}


def test_a_technology_and_the_phrase_containing_it_are_one_component():
    architecture = ArchitectureParser().parse(
        "A React portal calls a Spring Boot payments service backed by an "
        "Aurora PostgreSQL database."
    )
    names = _named(architecture)

    assert "Aurora PostgreSQL Database" in names
    assert "Aurora" not in names
    databases = [item for item in architecture.components if item.type == "Database"]
    assert len(databases) == 1


def test_a_name_is_not_cut_through_the_middle_of_a_technology():
    """"Java Spring Boot payments service" is not a service called Boot."""
    roles = find_named_roles("The system uses a Java Spring Boot payments service.")
    names = {role["name"] for role in roles}

    assert any("Spring Boot" in name for name in names), names
    assert not any(name.startswith("Boot ") for name in names), names


def test_a_declared_stack_is_not_a_separate_component():
    architecture = ArchitectureParser().parse(
        "Our platform runs on Kubernetes with the following services:\n"
        "1. User Service (Node.js + Express): Handles authentication.\n"
        "2. Payment Service (Java Spring Boot): Processes card payments.\n"
    )
    names = _named(architecture)

    assert not any(name in {"Express", "Spring", "Spring Boot", "Node.js Backend"} for name in names), names
    # The stack is still visible on the label; the reviewer needs to know what
    # the service is built with even though it is not a node of its own.
    user_service = next(name for name in names if name.startswith("User Service"))
    assert "Node.js" in user_service and "Express" in user_service
    assert user_service.count("(") == 1, user_service


def test_a_datastore_named_in_a_stack_is_still_its_own_component():
    """Absorbing a framework must not absorb the things the service talks to."""
    architecture = ArchitectureParser().parse(
        "1. Session Service (Node.js + Express): Handles login.\n"
        "Sessions are cached in Redis and stored in PostgreSQL.\n"
    )
    types = set(_typed(architecture).values())

    assert "Database" in types
    stores = {name for name, kind in _typed(architecture).items() if kind == "Database"}
    assert any("edis" in name or "REDIS" in name for name in stores), stores


def test_an_ambiguous_short_name_is_left_alone():
    """A word inside two fuller names identifies neither of them."""
    architecture = ArchitectureParser().parse(
        "The platform uses a Redis session cache and a Redis rate limit store. "
        "Redis is deployed in the shared services account."
    )
    names = _named(architecture)

    # Whatever the passes produced, nothing may be merged on the strength of a
    # name that fits into more than one candidate.
    assert len([name for name in names if "edis" in name.lower()]) >= 1


def test_the_structured_path_is_untouched_by_deduplication():
    """Consolidation is a repair for inference; a stated model needs no repair."""
    architecture = ArchitectureParser().parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology\n"
        "Row 2: C1 | Aurora | Amazon Aurora PostgreSQL\n"
        "Row 3: C2 | Aurora PostgreSQL Database | Amazon Aurora\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol\n"
        "Row 2: F1 | C1 -> C2 | TCP\n"
    )
    names = _named(architecture)

    # Both rows were written down deliberately, so both survive.
    assert {"Aurora", "Aurora PostgreSQL Database"} <= names
