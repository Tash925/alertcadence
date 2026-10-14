"""
AlertCadence — fetch + filter the CISA KEV feed.

Pulls the live Known Exploited Vulnerabilities feed, keeps only recent
advisories affecting software a small business would actually run, and
writes the shortlist to advisories.json for the rest of the pipeline.

Everything in KEV is already confirmed-exploited, so "is this a real
threat" is pre-filtered for us. We only add: recent + SMB-relevant.
"""

import json
import urllib.request
from datetime import datetime, timedelta, timezone

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# How far back to look for one newsletter issue.
DAYS_BACK = 30

# Hard cap so "tight" stays tight even in a busy month.
MAX_ADVISORIES = 6

# Vendors a small business plausibly runs. Matched case-insensitively as a
# substring of the KEV vendorProject field. Deliberately NOT enterprise/ICS
# gear (Siemens, Cisco ASA, Ivanti appliances) — a corner bakery doesn't run
# those, and surfacing them would make the newsletter feel irrelevant.
SMB_VENDORS = [
    "microsoft", "apple", "google", "adobe", "mozilla",
    "wordpress", "zoom", "dropbox", "atlassian", "zoho",
    "quickbooks", "intuit", "wpengine", "automattic",
    "oracle",  # (often = Java, which SMBs do run)
    "fortinet",  # common in small-office firewalls
]


def fetch_kev() -> dict:
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "AlertCadence/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def is_smb_relevant(advisory: dict) -> bool:
    vendor = (advisory.get("vendorProject", "") or "").lower()
    return any(v in vendor for v in SMB_VENDORS)


def is_recent(advisory: dict, cutoff: datetime) -> bool:
    raw = advisory.get("dateAdded", "")
    if not raw:
        return False
    try:
        return datetime.strptime(raw, "%Y-%m-%d") >= cutoff
    except ValueError:
        return False


def filter_advisories(feed: dict) -> list:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=DAYS_BACK)
    items = feed.get("vulnerabilities", [])

    recent_smb = [
        a for a in items
        if is_recent(a, cutoff) and is_smb_relevant(a)
    ]

    # Ransomware-flagged first (most urgent for a client), then newest.
    def sort_key(a):
        ransom = (a.get("knownRansomwareCampaignUse", "") or "").lower() == "known"
        return (0 if ransom else 1, a.get("dateAdded", ""))

    recent_smb.sort(key=sort_key, reverse=False)
    # Within the ransom/non-ransom groups we still want newest first:
    recent_smb.sort(
        key=lambda a: a.get("dateAdded", ""), reverse=True
    )
    recent_smb.sort(
        key=lambda a: (a.get("knownRansomwareCampaignUse", "") or "").lower() != "known"
    )

    return recent_smb[:MAX_ADVISORIES]


def main():
    print("Fetching CISA KEV feed...")
    feed = fetch_kev()
    total = len(feed.get("vulnerabilities", []))
    catalog_version = feed.get("catalogVersion", "unknown")
    print(f"  catalog version: {catalog_version}  ({total} total entries)")

    shortlist = filter_advisories(feed)
    print(f"  after filter (last {DAYS_BACK} days, SMB vendors): {len(shortlist)} advisories\n")

    for a in shortlist:
        ransom = "RANSOMWARE" if (a.get("knownRansomwareCampaignUse", "").lower() == "known") else ""
        print(f"  {a.get('dateAdded')}  {a.get('cveID')}  "
              f"{a.get('vendorProject')} {a.get('product')}  {ransom}")

    with open("advisories.json", "w") as f:
        json.dump(shortlist, f, indent=2)
    print(f"\nWrote {len(shortlist)} advisories to advisories.json")


if __name__ == "__main__":
    main()
