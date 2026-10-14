"""
AlertCadence — fact extractor.

Turns a raw CISA KEV advisory (messy free text) into a small, clean set of
facts that are safe to hand a 2B local model. The model never sees the raw
description, so exploit syntax / file paths / code can't leak into the
plain-English output.

Design note (from the Trail Edition finding): the guardrail that works isn't
a stricter prompt, it's a smaller job. This step IS that smaller job.
"""

import re


# Ordered most-specific first. Each entry: (regex to search in the raw
# description, plain-English flaw type for a non-technical reader).
# The regex is matched case-insensitively against the shortDescription.
FLAW_PATTERNS = [
    (r"remote code execution|execute arbitrary code|execute code|code injection|rce\b",
     "an attacker could run their own commands on the system from a distance"),
    (r"path traversal|directory traversal",
     "an attacker could reach files they were never meant to see"),
    (r"sql injection",
     "an attacker could trick the system into exposing or changing stored data"),
    (r"authentication bypass|bypass authentication|improper authentication|"
     r"bypass permission|improper authorization",
     "an attacker could get in or act without proper permission"),
    (r"privilege escalation|elevation of privilege|"
     r"gain .*privileges|escalate privileges",
     "an attacker could give themselves more control than they should have"),
    (r"buffer overflow|out-of-bounds|memory corruption|use[- ]after[- ]free",
     "a memory-handling flaw an attacker could use to take control"),
    (r"cross[- ]site scripting|xss\b",
     "an attacker could run malicious content inside a user's browser session"),
    (r"deserializ",
     "an attacker could abuse how the software reads saved data to run code"),
    (r"command injection|os command",
     "an attacker could sneak their own commands into the system"),
    (r"information disclosure|exposure of sensitive|leak",
     "the flaw could expose sensitive information to the wrong people"),
    (r"denial[- ]of[- ]service|dos\b",
     "an attacker could knock the system offline"),
    (r"improper access control|missing authorization|unauthorized access",
     "an attacker could access things they shouldn't be allowed to"),
]

# Safe fallback when nothing matches — honest and still useful.
GENERIC_FLAW = "a security weakness that attackers are known to be exploiting"


def extract_flaw_type(description: str) -> str:
    """Map a raw advisory description to one plain-English flaw type.

    Deterministic: the model only ever sees wording we chose here.
    """
    if not description:
        return GENERIC_FLAW
    text = description.lower()
    for pattern, plain in FLAW_PATTERNS:
        if re.search(pattern, text):
            return plain
    return GENERIC_FLAW


def is_vague(description: str) -> bool:
    """True when CISA gave us almost nothing to work with.

    These are the 'deliberately unanswerable' cases from the Trail Edition
    test — the ones where the model must admit uncertainty, not invent.
    """
    if not description:
        return True
    d = description.strip().lower()
    if len(d) < 40:
        return True
    if "unspecified" in d or "unknown vulnerability" in d:
        return True
    return False


def extract_facts(advisory: dict) -> dict:
    """Take one raw CISA KEV record, return only the clean facts the model
    is allowed to use.
    """
    description = advisory.get("shortDescription", "") or ""
    return {
        "cve_id": advisory.get("cveID", "").strip(),
        "vendor": (advisory.get("vendorProject", "") or "").strip(),
        "product": (advisory.get("product", "") or "").strip(),
        "flaw_type": extract_flaw_type(description),
        "ransomware": (advisory.get("knownRansomwareCampaignUse", "Unknown")
                       or "Unknown").strip().lower() == "known",
        "vague": is_vague(description),
        "date_added": advisory.get("dateAdded", "").strip(),
    }


if __name__ == "__main__":
    # Quick self-test with the two advisories we already know, plus a
    # deliberately thin one (the uncertainty test).
    samples = [
        {
            "cveID": "CVE-2021-3199",
            "vendorProject": "ONLYOFFICE",
            "product": "Document Server",
            "shortDescription": (
                "ONLYOFFICE Document Server contains a path traversal "
                "vulnerability via /.. that allows reading of arbitrary files."
            ),
            "knownRansomwareCampaignUse": "Unknown",
            "dateAdded": "2024-01-02",
        },
        {
            "cveID": "CVE-2024-TEST-APPLE",
            "vendorProject": "Apple",
            "product": "iOS and macOS",
            "shortDescription": (
                "Apple products contain a memory corruption vulnerability "
                "that could lead to arbitrary code execution."
            ),
            "knownRansomwareCampaignUse": "Known",
            "dateAdded": "2024-03-10",
        },
        {
            "cveID": "CVE-0000-VAGUE",
            "vendorProject": "ExampleCorp",
            "product": "WidgetServer",
            "shortDescription": "Unspecified vulnerability.",
            "knownRansomwareCampaignUse": "Unknown",
            "dateAdded": "2024-05-01",
        },
    ]
    for s in samples:
        facts = extract_facts(s)
        print(f"--- {facts['cve_id']} ---")
        for k, v in facts.items():
            print(f"  {k}: {v}")
        print()
