from __future__ import annotations

from primordial_preprocess.extraction.docling import _page_units


class FakeDoclingDocument:
    pages = {1: object(), 2: object()}

    def export_to_markdown(self, page_no=None):
        if page_no is None:
            return "full"
        return {1: "# Page One", 2: ""}[page_no]


def test_docling_page_units_preserve_page_numbers_and_warnings():
    units, warnings = _page_units(FakeDoclingDocument(), "full")

    assert units[0]["location_type"] == "page"
    assert units[0]["metadata"]["page"] == 1
    assert units[0]["text"] == "# Page One"
    assert units[1]["metadata"]["page"] == 2
    assert "no_text_on_page:2" in warnings
