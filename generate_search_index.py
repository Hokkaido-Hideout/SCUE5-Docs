# python generate_search_index.py README.md search-index.json
# Also indexes the adjacent infraction guide, when present.

import markdown2
from bs4 import BeautifulSoup
import json
import re
import sys
from pathlib import Path

def read_sections(md_path):
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    # Jekyll front matter is metadata, not searchable page text.
    md_text = re.sub(r"\A---\n.*?\n---\n", "", md_text, count=1, flags=re.S)
    html = markdown2.markdown(md_text, extras=["fenced-code-blocks", "header-ids", "tables"])
    soup = BeautifulSoup(html, "html.parser")

    sections = []
    current_section = {"id": "", "title": "", "body": ""}

    for element in soup.find_all(["h1", "h2", "h3", "h4", "p", "pre", "ul", "ol", "blockquote", "table"]):
        if element.name in ["h1", "h2", "h3"]:
            if current_section["title"]:
                sections.append(current_section)
            section_id = element.get("id")
            if not section_id:
                continue
            current_section = {
                "id": section_id,
                "title": element.get_text(),
                "body": ""
            }
        else:
            current_section["body"] += element.get_text(separator=" ", strip=True) + " "

    if current_section["title"]:
        sections.append(current_section)

    return sections

def generate_search_index(md_path, output_path):
    readme = Path(md_path)
    pages = [(readme, "/")]
    guide = readme.parent / "docs" / "InfractionReactions.md"
    if guide.is_file():
        pages.append((guide, "/docs/InfractionReactions.html"))
    sections = []
    for path, page_url in pages:
        for section in read_sections(path):
            anchor = section["id"]
            section["id"] = page_url + "#" + anchor
            section["url"] = page_url + "#" + anchor
            section["body"] = section["body"].strip()
            sections.append(section)
    if len({section["id"] for section in sections}) != len(sections):
        raise ValueError("Search index contains duplicate references")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sections, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python generate_search_index.py <README.md path> <output JSON path>")
    else:
        md_file = sys.argv[1]
        json_file = sys.argv[2]
        generate_search_index(md_file, json_file)
        print(f"Generated search index at: {json_file}")
