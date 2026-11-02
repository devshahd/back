# Database maintenance scripts

## Duplicate legacy categories

Run from the `backend` directory, with `DATABASE_URL` pointing to a **backup or test copy first**:

```powershell
python scripts/repair_legacy_categories.py
```

This is a dry run and does not modify data. It reports groups whose names differ only by letter case or surrounding whitespace.

After backing up the database and reviewing the dry-run report, apply the merge with:

```powershell
python scripts/repair_legacy_categories.py --apply --backup-confirmed
```

The script keeps the lowest-ID category as canonical, moves product references to it, preserves distinct descriptions, deletes only the duplicate category rows, and creates the case-insensitive unique index. It does not merge names that normalize to different values.
