"""Truncated model HTML must not tear the report apart.

In a September 2026 report, five of seven product groups ran into the model's
token limit. Their HTML stopped mid-tag — once in the middle of an attribute:

    <span style="display:inline-block;background:#fffde7;...;font-family:

`_append_table_to_section()` looked for the section's last `</div>`, found
none, and fell back to appending the findings table to that broken fragment.
The browser then read the appended `<details>` as attribute content of the
open tag and swallowed everything after it: the group's finding list
disappeared, and the next group card ended up nested inside the previous one.

The fallback itself was right — keep the table rather than lose it — it just
accepted unchecked fragments. These tests pin down that a section is repaired
into valid markup before anything is appended to it.
"""
import importlib.util
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load():
    path = ROOT / "patchday_backend.py"
    spec = importlib.util.spec_from_file_location("patchday_backend", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backend = _load()

TABLE = '<details style="margin-top:18px;"><summary>All 45 findings</summary></details>'

# The real break from the September report: cut inside a style attribute.
CUT_INSIDE_ATTRIBUTE = (
    '<div style="background:#fff;padding:25px;">'
    '<h2>Windows Server</h2><p>A paragraph about the situation.</p>'
    '<span style="display:inline-block;background:#fffde7;color:#f57f17;'
    'border:1px solid #ffe082;border-radius:3px;padding:1px 7px;'
    'font-size:11px;font-weight:700;font-family:'
)

# Another one: cut inside an href.
CUT_INSIDE_HREF = (
    '<div style="background:#fff;">'
    '<p>Action: install the latest security update.</p>'
    '<h3 style="font-size:1em;"><a href="https'
)

COMPLETE = (
    '<div style="background:#fff;padding:25px;">'
    '<h2>Developer Runtimes</h2><p>Everything closed properly.</p></div>'
)


def _open_tags(html):
    """Tags left open, void elements excluded."""
    void = {"br", "hr", "img", "input", "meta", "link", "col", "wbr"}
    stack = []
    for m in re.finditer(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>", html):
        slash, name, rest = m.group(1), m.group(2).lower(), m.group(3)
        if name in void or rest.rstrip().endswith("/"):
            continue
        if slash:
            if stack and stack[-1] == name:
                stack.pop()
        else:
            stack.append(name)
    return stack


# --- Repairing the section -------------------------------------------------

@pytest.mark.parametrize("raw", [CUT_INSIDE_ATTRIBUTE, CUT_INSIDE_HREF])
def test_half_written_tag_is_dropped(raw):
    """A half-written tag cannot be repaired — it has to go, not be patched."""
    clean = backend._sanitize_section_html(raw)
    assert "<" not in clean[clean.rfind(">") + 1:]


@pytest.mark.parametrize("raw", [CUT_INSIDE_ATTRIBUTE, CUT_INSIDE_HREF])
def test_open_tags_get_closed(raw):
    assert _open_tags(backend._sanitize_section_html(raw)) == []


def test_complete_section_is_left_alone():
    """Groups the model finished must not be touched."""
    assert backend._sanitize_section_html(COMPLETE) == COMPLETE


def test_no_content_is_lost():
    """Tidying up is not truncating."""
    clean = backend._sanitize_section_html(CUT_INSIDE_ATTRIBUTE)
    assert "Windows Server" in clean
    assert "A paragraph about the situation." in clean


def test_empty_section_stays_empty():
    assert backend._sanitize_section_html("") == ""


# --- Appending the findings table ------------------------------------------

@pytest.mark.parametrize("raw", [CUT_INSIDE_ATTRIBUTE, CUT_INSIDE_HREF, COMPLETE])
def test_table_lands_in_valid_html(raw):
    assert _open_tags(backend._append_table_to_section(raw, TABLE)) == []


@pytest.mark.parametrize("raw", [CUT_INSIDE_ATTRIBUTE, CUT_INSIDE_HREF, COMPLETE])
def test_table_stays_inside_the_group_card(raw):
    """It should inherit the card's frame and colour — so, before its </div>."""
    result = backend._append_table_to_section(raw, TABLE)
    assert result.rstrip().endswith("</div>")
    assert "<details" in result


@pytest.mark.parametrize("raw", [CUT_INSIDE_ATTRIBUTE, CUT_INSIDE_HREF])
def test_table_no_longer_sticks_to_an_open_tag(raw):
    """The actual defect: <details> read as attribute content of a broken tag."""
    result = backend._append_table_to_section(raw, TABLE)
    i = result.find("<details")
    before = result.rfind("<", 0, i)
    assert ">" in result[before:i], "the <details> still sits inside an open tag"


def test_without_a_table_the_section_is_untouched():
    assert backend._append_table_to_section(COMPLETE, "") == COMPLETE


def test_the_next_group_is_not_nested_inside_this_one():
    """Two sections in a row have to stay siblings."""
    a = backend._append_table_to_section(CUT_INSIDE_ATTRIBUTE, TABLE)
    b = backend._append_table_to_section(COMPLETE, TABLE)
    assert _open_tags(a + b) == []
