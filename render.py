"""
AlertCadence — render the newsletter.

Reads summaries.json (from build.py) and writes newsletter.html: one
branded, self-contained HTML security brief an MSP could send a
small-business client.

Warm-light editorial look: off-white paper, slate ink, a single muted
amber accent for attention, red reserved only for ransomware-linked items
(which are sorted to the top). Designed to read like a real business
email, not a dark AI dashboard.

    python3 render.py      # -> newsletter.html
"""

import html
import json
from datetime import datetime

# Placeholder MSP identity — a real MSP swaps these two lines.
MSP_NAME = "[Your Company] Managed IT"
MSP_TAGLINE = "Weekly Security Brief"


def esc(s: str) -> str:
    return html.escape(s or "")


def parse_boxes(summary: str) -> dict:
    boxes = {"WHAT HAPPENED": "", "WHY IT MATTERS TO YOUR BUSINESS": "",
             "WHAT WE'RE DOING": ""}
    current = None
    for line in summary.splitlines():
        line = line.strip()
        if not line:
            continue
        matched = False
        for label in boxes:
            if line.upper().startswith(label):
                current = label
                boxes[label] = line[len(label):].lstrip(": ").strip()
                matched = True
                break
        if not matched and current:
            boxes[current] += " " + line
    return boxes


def render_advisory(item: dict, n: int) -> str:
    boxes = parse_boxes(item["summary"])
    ransom = item.get("ransomware", False)
    flag = '<span class="flag">Active ransomware</span>' if ransom else ""
    num_class = "num ransom" if ransom else "num"
    card_class = "card ransom" if ransom else "card"

    return f"""
      <article class="{card_class}">
        <div class="card-top">
          <span class="{num_class}">{n}</span>
          <div class="card-id">
            <div class="tags">
              <span class="tag">CISA KEV</span>
              <span class="cve">{esc(item['cve_id'])}</span>
              {flag}
            </div>
            <h2>{esc(item['vendor'])} — {esc(item['product'])}</h2>
            <p class="added">Added {esc(item['date_added'])}</p>
          </div>
        </div>
        <div class="boxes">
          <div class="box">
            <span class="box-label">What happened</span>
            <p>{esc(boxes['WHAT HAPPENED'])}</p>
          </div>
          <div class="box">
            <span class="box-label">Why it matters to your business</span>
            <p>{esc(boxes['WHY IT MATTERS TO YOUR BUSINESS'])}</p>
          </div>
          <div class="box doing">
            <span class="box-label">What we're doing</span>
            <p>{esc(boxes["WHAT WE'RE DOING"])}</p>
          </div>
        </div>
        <a class="source" href="{esc(item['nvd_link'])}" target="_blank" rel="noopener">View the official advisory →</a>
      </article>"""


def render(items: list) -> str:
    today = datetime.now().strftime("%A, %B %-d, %Y")
    cards = "\n".join(render_advisory(it, i) for i, it in enumerate(items, 1))
    ransom_count = sum(1 for i in items if i.get("ransomware"))

    headline = f"{len(items)} things to patch this week"
    sub = "Pulled from CISA's exploited-vulnerability feed, filtered to the software small businesses run, and rewritten in plain English."
    if ransom_count:
        sub += f" {ransom_count} linked to active ransomware — listed first."

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(MSP_NAME)} — {esc(MSP_TAGLINE)}</title>
<style>
  :root {{
    --paper:#faf8f3; --card:#ffffff; --card-2:#f6f3ec;
    --ink:#1c2230; --ink-soft:#4a5160; --muted:#8a8f9c;
    --line:#e7e2d7; --line-soft:#efebe1;
    --accent:#b5792a;            /* muted amber — "attention", not alarm */
    --accent-soft:#f3e9d7;
    --warn:#c0392b; --warn-bg:#fbeeec; --warn-line:#eccfca;
    --ok:#2f8f5b;
    --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
    --serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,sans-serif;
  }}
  *{{box-sizing:border-box;}}
  body{{margin:0;background:var(--paper);color:var(--ink);
    font-family:var(--sans);line-height:1.62;
    -webkit-font-smoothing:antialiased;}}
  .wrap{{max-width:660px;margin:0 auto;padding:44px 22px 60px;}}
  .masthead{{display:flex;justify-content:space-between;align-items:baseline;
    border-bottom:2px solid var(--ink);padding-bottom:14px;margin-bottom:30px;}}
  .brand{{font-family:var(--mono);font-size:12px;letter-spacing:.14em;
    text-transform:uppercase;color:var(--ink);font-weight:600;}}
  .logo-dim{{font-family:var(--mono);font-size:11px;color:var(--muted);
    letter-spacing:.08em;}}
  .kicker{{font-family:var(--mono);font-size:11px;letter-spacing:.16em;
    color:var(--accent);text-transform:uppercase;margin:0 0 12px;font-weight:600;}}
  h1.headline{{font-family:var(--serif);font-size:32px;line-height:1.15;
    letter-spacing:-.01em;margin:0 0 12px;font-weight:600;}}
  .sub{{color:var(--ink-soft);font-size:15.5px;margin:0 0 36px;max-width:60ch;}}
  .card{{background:var(--card);border:1px solid var(--line);
    border-radius:12px;padding:24px;margin-bottom:18px;
    box-shadow:0 1px 2px rgba(28,34,48,.04);}}
  .card.ransom{{border-color:var(--warn-line);
    box-shadow:0 1px 2px rgba(192,57,43,.06);}}
  .card-top{{display:flex;gap:14px;align-items:flex-start;margin-bottom:18px;}}
  .num{{flex:none;width:28px;height:28px;border-radius:50%;
    background:var(--card-2);border:1px solid var(--line);color:var(--ink-soft);
    font-family:var(--mono);font-size:13px;font-weight:600;
    display:flex;align-items:center;justify-content:center;margin-top:2px;}}
  .num.ransom{{background:var(--warn);border-color:var(--warn);color:#fff;}}
  .card-id h2{{font-family:var(--serif);margin:9px 0 2px;font-size:20px;
    letter-spacing:-.01em;font-weight:600;}}
  .tags{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}}
  .tag{{font-family:var(--mono);font-size:10px;letter-spacing:.07em;
    text-transform:uppercase;color:var(--accent);background:var(--accent-soft);
    border-radius:5px;padding:2px 7px;font-weight:600;}}
  .cve{{font-family:var(--mono);font-size:12px;color:var(--muted);}}
  .flag{{font-family:var(--mono);font-size:10px;letter-spacing:.05em;
    text-transform:uppercase;color:var(--warn);background:var(--warn-bg);
    border:1px solid var(--warn-line);border-radius:999px;padding:2px 9px;font-weight:600;}}
  .added{{font-family:var(--mono);font-size:11px;color:var(--muted);margin:0;}}
  .boxes{{display:flex;flex-direction:column;gap:16px;}}
  .box-label{{font-family:var(--mono);font-size:10.5px;letter-spacing:.09em;
    text-transform:uppercase;color:var(--muted);display:block;margin-bottom:3px;}}
  .box p{{margin:0;font-size:15.5px;color:var(--ink);}}
  .box.doing{{background:var(--card-2);border-left:2px solid var(--ok);
    border-radius:8px;padding:13px 15px;}}
  .box.doing .box-label{{color:var(--ok);}}
  .source{{display:inline-block;margin-top:20px;font-family:var(--mono);
    font-size:12.5px;letter-spacing:.02em;color:var(--accent);
    text-decoration:none;border-bottom:1px solid var(--accent-soft);padding-bottom:2px;}}
  .source:hover{{border-color:var(--accent);}}
  footer{{margin-top:42px;padding-top:22px;border-top:1px solid var(--line);
    font-family:var(--mono);font-size:11px;line-height:1.9;color:var(--muted);
    letter-spacing:.02em;text-align:center;}}
  footer a{{color:var(--ink-soft);text-decoration:none;border-bottom:1px solid var(--line);}}
  footer a:hover{{color:var(--ink);}}
  .topnav{{max-width:660px;margin:0 auto;padding:16px 22px 0;}}
  .topnav a{{font-family:var(--mono);font-size:12px;letter-spacing:.04em;
    color:var(--muted);text-decoration:none;}}
  .topnav a:hover{{color:var(--ink);}}
  @media (max-width:480px){{h1.headline{{font-size:26px;}} .wrap{{padding:30px 16px 46px;}}}}
</style>
</head>
<body>
  <nav class="topnav"><a href="/">← AlertCadence</a></nav>
  <div class="wrap">
    <div class="masthead">
      <span class="brand">{esc(MSP_NAME)}</span>
      <span class="logo-dim">yourlogo.com</span>
    </div>
    <p class="kicker">{esc(today)} · Security Brief</p>
    <h1 class="headline">{esc(headline)}</h1>
    <p class="sub">{esc(sub)}</p>
    {cards}
    <footer>
      Generated locally with Gemma · No data leaves your machine<br>
      Source: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a> ·
      Built with <a href="https://alertcadence.tech">AlertCadence</a> ·
      Verify the official advisory before acting.
    </footer>
  </div>
</body>
</html>"""


def main():
    with open("summaries.json") as f:
        items = json.load(f)
    out = render(items)
    with open("newsletter.html", "w") as f:
        f.write(out)
    print(f"Wrote newsletter.html ({len(items)} advisories)")


if __name__ == "__main__":
    main()
