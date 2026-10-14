"""
AlertCadence — translate clean facts into the plain-English 3-box summary.

Runs on YOUR machine (where Ollama + gemma2:2b live). This container can't
reach your local Ollama, so run this locally:

    python3 translate.py

Pipeline per advisory:
    raw CISA record -> extract.py (clean facts) -> Gemma (rephrase only) -> 3 boxes

The model never sees the raw description. If a fact is vague, we tell the
model to admit it rather than guess (the Trail Edition uncertainty test).
"""

import json
import urllib.request

from extract import extract_facts


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "gemma2:2b"


def build_prompt(facts: dict) -> str:
    ransomware_line = (
        "Yes — this one is being used in active ransomware attacks."
        if facts["ransomware"]
        else "No known ransomware use reported."
    )

    # The vague case gets an explicit, sanctioned 'say so' instruction so the
    # model doesn't invent a mechanism that CISA never described.
    if facts["vague"]:
        certainty_rule = (
            "- The exact details of this issue are NOT public. In WHAT HAPPENED, "
            "say plainly that the specifics aren't public yet. Do NOT guess how "
            "the flaw works or invent any mechanism."
        )
    else:
        certainty_rule = (
            "- Use ONLY the facts listed. Do not add mechanisms or examples "
            "that are not stated here."
        )

    return f"""You rewrite a few known facts about a cybersecurity issue into plain English for a small-business owner who is NOT technical.

STRICT RULES:
{certainty_rule}
- If a fact is missing or vague, say so plainly. Never guess how the flaw works.
- Output PLAIN TEXT only. No markdown, headers, asterisks, or bullet symbols.
- No technical syntax, file paths, code, or exploit steps.
- Stay calm. Do not cause panic.

The facts:
Vendor: {facts['vendor']}
Product: {facts['product']}
What kind of problem: {facts['flaw_type']}
Used in ransomware attacks: {ransomware_line}

Write exactly three short parts, each 1-2 sentences. Start each part with its label on the same line:

WHAT HAPPENED: Describe the kind of problem in plain English, using only the facts above.
WHY IT MATTERS TO YOUR BUSINESS: The practical operational risk, in everyday terms.
WHAT WE'RE DOING: Reassuring, proactive language an MSP uses with a client (patching, monitoring).
"""


def call_gemma(prompt: str) -> str:
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        # Low temperature: we want faithful rephrasing, not creativity.
        "options": {"temperature": 0.3},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body.get("response", "").strip()


def translate(advisory: dict) -> dict:
    facts = extract_facts(advisory)
    prompt = build_prompt(facts)
    summary = call_gemma(prompt)
    return {"facts": facts, "summary": summary}


if __name__ == "__main__":
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
        result = translate(s)
        f = result["facts"]
        print("=" * 60)
        print(f"{f['cve_id']}  ({f['vendor']} {f['product']})")
        print(f"  flaw_type : {f['flaw_type']}")
        print(f"  vague     : {f['vague']}   ransomware: {f['ransomware']}")
        print("-" * 60)
        print(result["summary"])
        print()
