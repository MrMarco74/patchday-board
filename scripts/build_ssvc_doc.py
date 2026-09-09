#!/usr/bin/env python3
"""Builds ssvc_doku.html from docs/SSVC.md.

Die Markdown-Datei ist die Quelle; die HTML-Fassung wird generiert, damit
beide nicht auseinanderlaufen koennen. Bewusst ohne Markdown-Bibliothek: das
Dokument benutzt eine feste, kleine Teilmenge (Ueberschriften, Tabellen,
Codebloecke, Listen, fett/inline-code, Trennlinien), und eine weitere
Laufzeitabhaengigkeit fuer einen Build-Schritt waere unverhaeltnismaessig.

Aufruf:  python3 scripts/build_ssvc_doc.py
"""
import html
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "SSVC.md"
DST = ROOT / "ssvc_doku.html"

# Farben aus _SSVC_STYLES in patchday_backend.py — dieselbe Palette wie im
# Bericht, damit die Doku nicht andere Farben erklaert als sie zeigt.
SSVC_COLORS = {
    "Act": ("#b71c1c", "#fdecea"),
    "Attend": ("#e65100", "#fff3e0"),
    "Track*": ("#f57f17", "#fffde7"),
    "Track": ("#2e7d32", "#e8f5e9"),
}


def inline(text: str) -> str:
    """Inline-Auszeichnung. Escaped zuerst, damit im Markdown stehendes HTML
    als Text erscheint und nicht als Markup."""
    out = html.escape(text, quote=False)
    out = re.sub(r"`([^`]+)`", r'<code>\1</code>', out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    # \* ist im Fliesstext ein maskierter Stern (Track\*), kein Markup
    out = out.replace("\\*", "*")
    return out


def cell(text: str) -> str:
    """Tabellenzelle — SSVC-Stufen darin bekommen ihre Berichtsfarbe."""
    stripped = text.strip().strip("*").replace("\\", "")
    if stripped in SSVC_COLORS:
        fg, bg = SSVC_COLORS[stripped]
        return (f'<span style="background:{bg};color:{fg};padding:1px 7px;'
                f'border-radius:3px;font-weight:700;">{html.escape(stripped)}</span>')
    return inline(text.strip())


def render(md: str) -> str:
    out, lines, i = [], md.splitlines(), 0
    while i < len(lines):
        line = lines[i]

        if line.startswith("```"):
            block = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>" + html.escape("\n".join(block)) + "</code></pre>")
            continue

        # Tabelle: Kopfzeile, Trennzeile, dann Datenzeilen
        if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1]):
            head = [c.strip() for c in line.strip("|").split("|")]
            i += 2
            body = []
            while i < len(lines) and lines[i].startswith("|"):
                body.append([c.strip() for c in lines[i].strip("|").split("|")])
                i += 1
            th = "".join(f"<th>{inline(h)}</th>" for h in head)
            tr = "".join("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in row) + "</tr>"
                         for row in body)
            out.append(f'<div class="tw"><table><thead><tr>{th}</tr></thead>'
                       f"<tbody>{tr}</tbody></table></div>")
            continue

        if line.startswith("#"):
            lvl = len(line) - len(line.lstrip("#"))
            out.append(f"<h{lvl}>{inline(line.lstrip('# '))}</h{lvl}>")
            i += 1
            continue

        if line.strip() == "---":
            out.append("<hr>")
            i += 1
            continue

        if line.startswith(("- ", "* ")):
            items = []
            while i < len(lines) and lines[i].startswith(("- ", "* ")):
                items.append(f"<li>{inline(lines[i][2:])}</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue

        if not line.strip():
            i += 1
            continue

        para = []
        while i < len(lines) and lines[i].strip() and not lines[i].startswith(
                ("#", "|", "```", "- ", "* ")) and lines[i].strip() != "---":
            para.append(lines[i])
            i += 1
        out.append("<p>" + inline(" ".join(para)) + "</p>")

    return "\n".join(out)


CSS = """
:root { color-scheme: light; }
body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
       line-height: 1.65; color: #24292f; background: #f4f4f4;
       margin: 0; padding: 24px; }
.wrap { max-width: 940px; margin: 0 auto; background: #fff; padding: 40px 48px;
        border: 1px solid #d8dee4; border-radius: 8px; }
h1 { font-size: 26px; color: #004578; margin: 0 0 6px; }
h2 { font-size: 19px; margin: 34px 0 10px; padding-bottom: 6px;
     border-bottom: 2px solid #eaeef2; }
h3 { font-size: 15px; margin: 22px 0 8px; color: #444; }
p { margin: 10px 0; }
code { background: #f0f2f5; padding: 1px 5px; border-radius: 3px;
       font-family: ui-monospace, Consolas, monospace; font-size: 12.5px; }
pre { background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 6px;
      padding: 14px 16px; overflow-x: auto; }
pre code { background: none; padding: 0; font-size: 12.5px; line-height: 1.5; }
.tw { overflow-x: auto; margin: 14px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th { background: #004578; color: #fff; text-align: left; padding: 8px 10px;
     font-size: 12px; white-space: nowrap; }
td { padding: 7px 10px; border-bottom: 1px solid #eaeef2; vertical-align: top; }
tr:last-child td { border-bottom: none; }
ul { margin: 10px 0; padding-left: 22px; }
li { margin: 4px 0; }
hr { border: none; border-top: 1px solid #eaeef2; margin: 30px 0; }
strong { color: #1a1a1a; }
.foot { margin-top: 34px; padding-top: 14px; border-top: 1px solid #eaeef2;
        font-size: 12px; color: #777; }
"""


def main() -> int:
    if not SRC.exists():
        print(f"fehlt: {SRC}", file=sys.stderr)
        return 1
    md = SRC.read_text(encoding="utf-8")
    title = md.splitlines()[0].lstrip("# ").strip()
    doc = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n"
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f"<title>{html.escape(title)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n"
        f'<div class="wrap">\n{render(md)}\n'
        '<p class="foot">Generated from <code>docs/SSVC.md</code> by '
        "<code>scripts/build_ssvc_doc.py</code> — edit the Markdown, not this "
        "file.</p>\n"
        "</div>\n</body>\n</html>\n"
    )
    DST.write_text(doc, encoding="utf-8")
    print(f"{DST.name}: {len(doc)} Bytes aus {SRC.name} ({len(md)} Bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
