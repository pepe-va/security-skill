#!/usr/bin/env python3
"""Generate the OWASP Agentic AI - Threats and Mitigations 1.1 reference from the official PDF."""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

from pypdf import PdfReader

logging.disable(logging.CRITICAL)

RESOURCE = "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/"
SOURCE_PDF = (
    "https://raw.githubusercontent.com/GenAI-Security-Project/GenAI-Security-Advisor/"
    "main/corpus/agentic-top10/companions/Agentic-AI-Threats-and-Mitigations-1.1.pdf"
)
VERSION = "1.1 (December 2025)"
LICENSE = "CC BY-SA 4.0"

# PDF pages (0-based) holding the "Detailed Threat Model" table.
TABLE_PAGES = range(16, 20)
# PDF pages (0-based) of the prose sections.
NAVIGATOR_PAGES = range(21, 34)
MITIGATIONS_PAGES = range(34, 43)
EXAMPLES_PAGES = range(43, 50)
# Prose that closes the threat model, after the table.
TAXONOMY_NOTE_PAGES = range(19, 21)

# "Playbook and Threat Mapping Overview" table: region it occupies on each page.
MAPPING_REGION = {34: (-10**9, -1350), 35: (100, 10**9)}
MAPPING_SPLIT = 1000

# Headings the PDF marks only typographically; promoted here to level 3.
PROMOTED = re.compile(
    r"^(?:[\U0001F300-\U0001FAFF\u2190-\u2BFF\uFE0F]\s*)*"
    r"(?:(?:\u25b6\s*)?Step \d+[:.]|Playbook \d+[:.]|Example \d+[:.]|Example:|Risk:)"
)

# Horizontal bounds of the table's four columns.
COLUMNS = ((350, "tid"), (700, "name"), (1400, "desc"), (10**9, "mit"))

# Editorial routing: each threat with the ASI risk and the SC controls that cover it.
ROUTING = {
    "T1": ("ASI06", ["SC-AI-04", "SC-IN-02"]),
    "T2": ("ASI02", ["SC-AI-02", "SC-AI-03", "SC-AUTH-03"]),
    "T3": ("ASI03", ["SC-AUTH-02", "SC-AUTH-03", "SC-AI-03"]),
    "T4": ("ASI08", ["SC-AI-07", "SC-CFG-01"]),
    "T5": ("ASI08", ["SC-AI-05", "SC-OUT-01"]),
    "T6": ("ASI01", ["SC-AI-01", "SC-IN-01", "SC-IN-03"]),
    "T7": ("ASI01", ["SC-AI-01", "SC-AI-06", "SC-LOG-02"]),
    "T8": ("ASI09", ["SC-LOG-01", "SC-LOG-02"]),
    "T9": ("ASI03", ["SC-AUTH-01", "SC-AUTH-02"]),
    "T10": ("ASI09", ["SC-AI-06", "SC-AI-09"]),
    "T11": ("ASI05", ["SC-AI-08", "SC-SEC-01", "SC-SEC-02"]),
    "T12": ("ASI07", ["SC-AI-10", "SC-TLS-01", "SC-IN-02"]),
    "T13": ("ASI10", ["SC-AI-09", "SC-LOG-02"]),
    "T14": ("ASI10", ["SC-AUTH-02", "SC-AI-09"]),
    "T15": ("ASI09", ["SC-AI-06", "SC-OUT-01"]),
    "T16": ("ASI07", ["SC-AI-10", "SC-TLS-01"]),
    "T17": ("ASI04", ["SC-SUP-01", "SC-SUP-02", "SC-SUP-03"]),
}


def column(x: float) -> str:
    """Return the name of the column at this horizontal coordinate."""
    for limit, name in COLUMNS:
        if x < limit:
            return name
    raise AssertionError


def positioned(page) -> list[tuple[float, float, str]]:
    """Extract a page's text fragments with their coordinates."""
    items: list[tuple[float, float, str]] = []

    def visit(text, cm, tm, font_dict, font_size):
        # Whitespace-only fragments carry their own font: keep them.
        if text and text != "\n":
            items.append((round(tm[5], 1), round(tm[4], 1), text))

    page.extract_text(visitor_text=visit)
    return [item for item in items if item[0] > -2300]  # drop the page footer


def squeeze(text: str) -> str:
    """Normalise whitespace in a cell."""
    return re.sub(r"\s+", " ", text).strip()


def parse_table(reader: PdfReader) -> list[dict[str, str]]:
    """Rebuild the Detailed Threat Model table by splitting cells on coordinates."""
    rows: list[dict[str, str]] = []
    for index in TABLE_PAGES:
        items = positioned(reader.pages[index])
        starts = sorted(
            (y, t.strip())
            for y, x, t in items
            if column(x) == "tid" and re.fullmatch(r"T\d+", t.strip())
        )
        starts.reverse()
        # Prose after the table sits in the left column without being a TID.
        tail = [
            y
            for y, x, t in items
            if column(x) == "tid" and t.strip() and not re.fullmatch(r"T\d+", t.strip())
        ]
        for position, (y_start, tid) in enumerate(starts):
            if position + 1 < len(starts):
                y_end = starts[position + 1][0]
            else:
                below = [y for y in tail if y < y_start]
                y_end = max(below) if below else -(10**9)
            cell = {"tid": tid, "name": "", "desc": "", "mit": ""}
            for y, x, t in sorted(items, key=lambda item: (-item[0], item[1])):
                if y_end < y <= y_start and column(x) != "tid":
                    cell[column(x)] += t
            rows.append({k: squeeze(v) if k != "tid" else v for k, v in cell.items()})
    return rows


def parse_mapping(reader: PdfReader) -> list[tuple[str, str]]:
    """Rebuild the Playbook / Threats Covered table by splitting its two columns."""
    rows: list[tuple[str, str]] = []
    for index, (low, high) in MAPPING_REGION.items():
        items = [item for item in positioned(reader.pages[index]) if low <= item[0] <= high]
        starts = sorted(
            (y for y, x, t in items if x < 300 and re.fullmatch(r"\d+\.", t.strip())),
            reverse=True,
        )
        for position, y_start in enumerate(starts):
            y_end = starts[position + 1] if position + 1 < len(starts) else low
            left, right = "", ""
            for y, x, t in sorted(items, key=lambda item: (-item[0], item[1])):
                if not (y_end < y <= y_start) or x < 280:
                    continue
                if x < MAPPING_SPLIT:
                    left += t
                else:
                    right += t
            if rows and not left.strip():  # continuation of the previous row
                rows[-1] = (rows[-1][0], squeeze(rows[-1][1] + " " + right))
            else:
                rows.append((squeeze(left), squeeze(right)))
    if len(rows) != 6:
        sys.exit(f"expected 6 playbooks in the mapping table, extracted {len(rows)}")
    return rows


def prose(reader: PdfReader, pages) -> str:
    """Extract running text from a page range, dropping headers and footers."""
    out: list[str] = []
    for index in pages:
        text = reader.pages[index].extract_text() or ""
        text = re.sub(r"^\s*Page \d+\s*$", "", text, flags=re.M)
        text = re.sub(r"^\s*genai\.owasp\.org\s*$", "", text, flags=re.M)
        out.append(text)
    body = "\n".join(out)
    body = re.sub(r"[ \t]+\n", "\n", body)
    body = re.sub(r"\n{3,}", "\n\n", body)
    return body.strip()


def to_markdown(body: str, title: str, headings: set[str]) -> str:
    """Turn PDF prose into markdown: bullets, headings and line-break hyphens."""
    # The section title arrives split over several lines at the top: drop it.
    words = title.split()
    while words:
        pattern = r"\A\s*" + r"\s*".join(map(re.escape, words)) + r"\s*\n"
        if re.match(pattern, body):
            body = re.sub(pattern, "", body)
            break
        words.pop()
    # In this PDF a hyphen at line end belongs to a real compound
    # (decision-making, AI-driven...), not to syllable splitting: rejoin it.
    body = re.sub(r"(\w)-\s+(\w)", r"\1-\2", body)
    lines = [line.rstrip() for line in body.split("\n")]
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            out.append("")
            continue
        bullet = re.match(r"^([●•])\s*(.*)$", stripped)
        if bullet:
            out.append(f"- {bullet.group(2)}")
            continue
        sub = re.match(r"^([○■])\s*(.*)$", stripped)
        if sub:
            out.append(f"  - {sub.group(2)}")
            continue
        if stripped in headings or PROMOTED.match(stripped):
            out.append("")
            out.append(f"### {stripped}")
            out.append("")
            continue
        if out and out[-1] and stripped[:1].islower():
            out[-1] += " " + stripped
            continue
        out.append(stripped)
    text = "\n".join(out)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def build(pdf: Path) -> str:
    reader = PdfReader(str(pdf))
    rows = parse_table(reader)
    if len(rows) != 17:
        sys.exit(f"expected 17 threats, extracted {len(rows)}")

    parts = [
        "# OWASP Agentic AI — Threats and Mitigations",
        "",
        f"- **Version:** {VERSION}",
        f"- **Published by:** OWASP Top 10 for LLM Apps & Gen AI — Agentic Security Initiative (ASI)",
        f"- **Resource:** {RESOURCE}",
        f"- **Source PDF:** {SOURCE_PDF}",
        f"- **Licence:** {LICENSE}",
        "",
        "Companion guide to the *OWASP Top 10 for Agentic Applications*. It defines the",
        "**T1–T17** agentic threat taxonomy that the ASI risks cross-reference (for example,",
        "ASI01 refers to T6 and T7).",
        "",
        "> Generated by `scripts/gen_threats.py` from the official PDF. Do not edit by hand: regenerate.",
        "> The normative text of the tables and sections below is reproduced as it appears in the",
        "> official PDF. The **Routing in this skill** blocks are editorial and not part of the guide.",
        "",
        "## Agentic threat taxonomy (T1–T17)",
        "",
        "| TID | Threat Name | ASI | SC controls |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        asi, controls = ROUTING[row["tid"]]
        anchor = row["name"].lower().replace(" ", "-")
        anchor = re.sub(r"[^a-z0-9-]", "", anchor)
        parts.append(
            f"| {row['tid']} | [{row['name']}](#{row['tid'].lower()}-{anchor}) "
            f"| {asi} | {', '.join(controls)} |"
        )
    note = prose(reader, TAXONOMY_NOTE_PAGES)
    note = note[note.index("Our taxonomy draws") :]
    parts += ["", "### Origin of the taxonomy (note from the guide)", "", to_markdown(note, "", set())]
    parts.append("")
    parts.append("## Detailed Threat Model")
    parts.append("")
    for row in rows:
        asi, controls = ROUTING[row["tid"]]
        parts += [
            f"### {row['tid']} {row['name']}",
            "",
            "**Threat Description**",
            "",
            row["desc"],
            "",
            "**Mitigations**",
            "",
            row["mit"],
            "",
            f"**Routing in this skill** — agentic risk: **{asi}**. "
            f"Controls: {', '.join(controls)}.",
            "",
        ]

    # The navigator names threats with "and" where the table uses "&".
    headings = {row["name"] for row in rows}
    headings |= {name.replace(" & ", " and ") for name in headings}
    headings |= {
        "Agentic Threat Decision Path",
        "Playbook and Threat Mapping Overview",
    }

    mapping = parse_mapping(reader)
    table = ["| Playbook | Threats Covered |", "| --- | --- |"]
    table += [f"| {playbook} | {threats} |" for playbook, threats in mapping]

    for title, pages in (
        ("Agentic Threats Taxonomy Navigator", NAVIGATOR_PAGES),
        ("Mitigation Strategies", MITIGATIONS_PAGES),
        ("Example Threat Models", EXAMPLES_PAGES),
    ):
        body = to_markdown(prose(reader, pages), title, headings)
        if title == "Mitigation Strategies":
            # The block between the table heading and the first playbook comes out
            # flattened when two columns are extracted: replace it with the rebuilt table.
            head, _, rest = body.partition("### Playbook and Threat Mapping Overview")
            _, marker, tail = rest.partition("### \U0001f539 Playbook 1")
            body = "\n".join(
                [head.rstrip(), "", "### Playbook and Threat Mapping Overview", ""]
                + table
                + ["", marker + tail]
            )
        parts += [f"## {title}", "", body, ""]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(parts)) + "\n"


def main() -> None:
    scripts = Path(__file__).resolve().parent
    pdf = Path(sys.argv[1]) if len(sys.argv) > 1 else scripts.parent / "sources" / "threats-1.1.pdf"
    if not pdf.exists():
        sys.exit(f"source PDF not found: {pdf}\ndownload it from {SOURCE_PDF}")
    target = scripts.parent / "skills" / "security" / "cybersec-skill" / "references" / "standards" / "owasp-agentic-threats-mitigations-1.1.md"
    target.write_text(build(pdf), encoding="utf-8")
    print(f"{target.name}: {len(target.read_text(encoding='utf-8').splitlines())} lines")


if __name__ == "__main__":
    main()
