from __future__ import annotations

from primordial_preprocess.epub_convert import convert_epub_with_pandoc


def test_epub_conversion_does_not_fallback_when_pandoc_missing(monkeypatch, tmp_path):
    source = tmp_path / "book.epub"
    source.write_bytes(b"not-real-epub")
    output = tmp_path / "out.md"
    monkeypatch.setattr("primordial_preprocess.epub_convert.shutil.which", lambda name: None)

    result = convert_epub_with_pandoc(source, output)

    assert result["converted"] is False
    assert result["method"] == "pandoc"
    assert "fallback extractors are disabled" in result["error"]
    assert not output.exists()
