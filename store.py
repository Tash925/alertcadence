"""
AlertCadence — storage layer.

Stores each week's advisories + plain-English summaries in MongoDB, so the
pipeline keeps a durable history of every brief it has generated (not just
the latest HTML). Each advisory is upserted by CVE id, so re-running the
pipeline updates existing records instead of duplicating them.

Graceful fallback: if MongoDB isn't configured or can't be reached, it
writes the same records to a local JSON file (storage_fallback.json) and
says so — so the pipeline never breaks just because the database is down.

Setup (one time, on your machine):
    pip install pymongo
    export ALERTCADENCE_MONGO_URI="mongodb+srv://<user>:<pass>@<cluster>.mongodb.net/"

Then, after build.py has written summaries.json:
    python3 store.py        # reads summaries.json -> MongoDB (or fallback)
"""

import json
import os
from datetime import datetime, timezone

DB_NAME = "alertcadence"
COLLECTION = "advisories"
FALLBACK_FILE = "storage_fallback.json"


def _records_from_summaries(path: str = "summaries.json") -> list:
    """Load the pipeline's output and stamp each record with when it was stored."""
    with open(path) as f:
        items = json.load(f)
    stored_at = datetime.now(timezone.utc).isoformat()
    for it in items:
        it["stored_at"] = stored_at
    return items


def _store_local(records: list) -> None:
    """Fallback: append this run's records to a local JSON file."""
    existing = []
    if os.path.exists(FALLBACK_FILE):
        try:
            with open(FALLBACK_FILE) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            existing = []
    # De-dupe by cve_id + stored_at run, keeping newest write per cve.
    by_cve = {r["cve_id"]: r for r in existing}
    for r in records:
        by_cve[r["cve_id"]] = r
    with open(FALLBACK_FILE, "w") as f:
        json.dump(list(by_cve.values()), f, indent=2)


def store(records: list) -> str:
    """Store records in MongoDB; fall back to local JSON on any failure.

    Returns a short human-readable status string.
    """
    uri = os.environ.get("ALERTCADENCE_MONGO_URI")

    if not uri:
        _store_local(records)
        return (f"No ALERTCADENCE_MONGO_URI set — stored {len(records)} "
                f"records locally in {FALLBACK_FILE}. "
                f"(Set the env var to use MongoDB.)")

    try:
        from pymongo import MongoClient, UpdateOne
        from pymongo.errors import PyMongoError

        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")  # fail fast if unreachable
        col = client[DB_NAME][COLLECTION]

        # Upsert by CVE id so re-runs update instead of duplicate.
        ops = [
            UpdateOne({"cve_id": r["cve_id"]}, {"$set": r}, upsert=True)
            for r in records
        ]
        result = col.bulk_write(ops)
        total = col.count_documents({})
        return (f"Stored {len(records)} records in MongoDB "
                f"({result.upserted_count} new, "
                f"{result.modified_count} updated). "
                f"Collection now holds {total} advisories.")

    except Exception as e:  # noqa: BLE001 — any failure should fall back
        _store_local(records)
        return (f"MongoDB unavailable ({type(e).__name__}) — "
                f"stored {len(records)} records locally in {FALLBACK_FILE} "
                f"instead. The pipeline is unaffected.")


def main():
    records = _records_from_summaries()
    print(store(records))


if __name__ == "__main__":
    main()
