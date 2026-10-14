"""
AlertCadence — run the full engine on the fetched advisories.

Reads advisories.json (from fetch.py), extracts clean facts, runs each
through Gemma for the 3-box plain-English summary, and writes summaries.json
for the HTML renderer.

Run order:
    python3 fetch.py      # -> advisories.json
    python3 build.py      # -> summaries.json   (needs Ollama running)
"""

import json

from extract import extract_facts
from translate import build_prompt, call_gemma


def main():
    with open("advisories.json") as f:
        advisories = json.load(f)

    print(f"Running {len(advisories)} advisories through Gemma...\n")

    results = []
    for i, advisory in enumerate(advisories, 1):
        facts = extract_facts(advisory)
        print(f"[{i}/{len(advisories)}] {facts['cve_id']}  "
              f"({facts['vendor']} {facts['product']})  "
              f"flaw: {facts['flaw_type']}"
              f"{'  [VAGUE]' if facts['vague'] else ''}")

        prompt = build_prompt(facts)
        summary = call_gemma(prompt)

        results.append({
            "cve_id": facts["cve_id"],
            "vendor": facts["vendor"],
            "product": facts["product"],
            "date_added": facts["date_added"],
            "ransomware": facts["ransomware"],
            "vague": facts["vague"],
            # Link back to the authoritative source for each advisory.
            "nvd_link": f"https://nvd.nist.gov/vuln/detail/{facts['cve_id']}",
            "summary": summary,
        })

    with open("summaries.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nWrote {len(results)} summaries to summaries.json")


if __name__ == "__main__":
    main()
