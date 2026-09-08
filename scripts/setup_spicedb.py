"""Setup and seed script applying the ReBAC Zed schema and sample relationships to SpiceDB."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.common.schemas import RelationshipTuple, Resource, Subject
from app.policy.client import SpiceDBClient

SCHEMA_PATH = Path(__file__).parent.parent / "app" / "policy" / "schema.zed"


def seed_spicedb(client: SpiceDBClient) -> None:
    """Apply Zed schema and insert initial test relationships."""
    if not SCHEMA_PATH.exists():
        print(f"Error: Schema file not found at {SCHEMA_PATH}")
        sys.exit(1)

    schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
    print(f"Applying schema from {SCHEMA_PATH} to SpiceDB at {client.endpoint}...")
    client.write_schema(schema_text)
    print("Schema applied successfully.\n")

    print("Seeding initial ReBAC relationships...")
    relationships = [
        # Team memberships
        RelationshipTuple(
            resource=Resource(type="team", id="eng"),
            relation="member",
            subject=Subject(type="user", id="alice"),
        ),
        RelationshipTuple(
            resource=Resource(type="team", id="eng"),
            relation="member",
            subject=Subject(type="user", id="bob"),
        ),
        RelationshipTuple(
            resource=Resource(type="team", id="security"),
            relation="admin",
            subject=Subject(type="user", id="charlie"),
        ),
        # Document permissions
        RelationshipTuple(
            resource=Resource(type="document", id="doc1"),
            relation="reader",
            subject=Subject(type="team", id="eng", relation="member"),
        ),
        RelationshipTuple(
            resource=Resource(type="document", id="doc1"),
            relation="writer",
            subject=Subject(type="team", id="security", relation="admin"),
        ),
        RelationshipTuple(
            resource=Resource(type="document", id="financials"),
            relation="reader",
            subject=Subject(type="team", id="security", relation="admin"),
        ),
    ]

    client.write_relationships(relationships)
    print(f"Successfully seeded {len(relationships)} relationships into SpiceDB:")
    for rel in relationships:
        print(f"  + {rel.resource}#{rel.relation} -> {rel.subject}")


def main() -> None:
    """Main execution point with retry backoff for container environments."""
    import time
    client = SpiceDBClient()
    max_retries = 15
    for attempt in range(1, max_retries + 1):
        try:
            print(f"Connecting to SpiceDB at {client.endpoint} (attempt {attempt}/{max_retries})...")
            seed_spicedb(client)
            print("SpiceDB initialization and seeding complete.")
            return
        except Exception as exc:
            print(f"Attempt {attempt} failed: {exc}")
            if attempt < max_retries:
                time.sleep(2)
            else:
                print("Exhausted retries connecting to SpiceDB.")
                sys.exit(1)


if __name__ == "__main__":
    main()
