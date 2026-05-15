from __future__ import annotations

from primordial_preprocess.hashing import sha256_file, stable_id
from primordial_preprocess.inventory import inventory_directory


def test_duplicate_hashing_marks_canonical_copy(tmp_path):
    (tmp_path / "a.pdf").write_text("same", encoding="utf-8")
    (tmp_path / "b.pdf").write_text("same", encoding="utf-8")

    records = inventory_directory(tmp_path)

    assert sha256_file(tmp_path / "a.pdf") == sha256_file(tmp_path / "b.pdf")
    assert len({record["possible_duplicate_group"] for record in records}) == 1
    assert sum(1 for record in records if record["recommended_keep"]) == 1
    assert sum(1 for record in records if not record["recommended_keep"]) == 1


def test_stable_id_is_deterministic():
    assert stable_id("chunk", "source", 1, "text") == stable_id("chunk", "source", 1, "text")
