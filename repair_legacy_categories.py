"""Safely merge case/whitespace-only duplicate categories in an existing PharmaSys DB.

Dry-run by default. To modify a database, make a backup first and pass BOTH
--apply and --backup-confirmed. Products are reassigned to the lowest-ID category;
non-empty descriptions are preserved by joining distinct values. Only categories
whose lower(trim(name)) values match exactly are merged.
"""
import argparse
import sys
from pathlib import Path
from collections import defaultdict
from sqlalchemy import inspect, text
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.database import engine


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="apply the merge (default is report only)")
    parser.add_argument("--backup-confirmed", action="store_true", help="confirm a tested database backup exists")
    args = parser.parse_args()
    if args.apply and not args.backup_confirmed:
        parser.error("--apply requires --backup-confirmed after making a database backup")

    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if "categories" not in tables:
        print("No categories table; nothing to do.")
        return 0
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT id, name, description FROM categories ORDER BY id")).mappings().all()
    groups = defaultdict(list)
    for row in rows:
        groups[(row["name"] or "").strip().lower()].append(dict(row))
    duplicates = {key: values for key, values in groups.items() if len(values) > 1}
    if not duplicates:
        print("No legacy duplicate category names found.")
        return 0

    print("Duplicate category groups (canonical category = lowest ID):")
    for normalized, values in duplicates.items():
        print(f"  normalized={normalized!r}; ids={[int(v['id']) for v in values]}; names={[v['name'] for v in values]!r}")
    if not args.apply:
        print("DRY RUN ONLY: no data changed. Back up the DB, review this report, then rerun with --apply --backup-confirmed.")
        return 0

    has_products = "products" in tables and "category_id" in {c["name"] for c in inspector.get_columns("products")}
    with engine.begin() as conn:
        for normalized, values in duplicates.items():
            canonical = values[0]
            canonical_id = int(canonical["id"])
            descriptions = []
            for row in values:
                value = (row.get("description") or "").strip()
                if value and value not in descriptions:
                    descriptions.append(value)
            conn.execute(text("UPDATE categories SET name=:name, description=:description WHERE id=:id"), {
                "name": (canonical.get("name") or "").strip(),
                "description": " | ".join(descriptions) or None,
                "id": canonical_id,
            })
            for row in values[1:]:
                duplicate_id = int(row["id"])
                if has_products:
                    conn.execute(text("UPDATE products SET category_id=:canonical WHERE category_id=:duplicate"), {
                        "canonical": canonical_id, "duplicate": duplicate_id
                    })
                conn.execute(text("DELETE FROM categories WHERE id=:id"), {"id": duplicate_id})
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_categories_name_lower ON categories (lower(trim(name)))"))
    print(f"Applied merge to {len(duplicates)} duplicate group(s), preserved product category references, and created the unique index.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
