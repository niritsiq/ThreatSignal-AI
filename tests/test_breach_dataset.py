"""Tests for breach_dataset — load_cases and save_cases utilities."""

from __future__ import annotations

from pathlib import Path

from threatsignal.embeddings.breach_dataset import load_cases, save_cases


def test_load_cases_missing_file_returns_empty(tmp_path):
    result = load_cases(str(tmp_path / "nonexistent.jsonl"))
    assert result == []


def test_save_and_load_round_trip(tmp_path):
    cases = [{"case_id": "c1", "title": "Test Breach", "year": 2023}]
    path = str(tmp_path / "cases.jsonl")
    save_cases(cases, path)
    loaded = load_cases(path)
    assert loaded == cases


def test_save_creates_parent_dirs(tmp_path):
    cases = [{"case_id": "c2"}]
    path = str(tmp_path / "subdir" / "nested" / "cases.jsonl")
    save_cases(cases, path)
    assert Path(path).exists()


def test_load_skips_blank_lines(tmp_path):
    path = tmp_path / "cases.jsonl"
    path.write_text('{"case_id": "c1"}\n\n{"case_id": "c2"}\n', encoding="utf-8")
    result = load_cases(str(path))
    assert len(result) == 2
    assert result[0]["case_id"] == "c1"
    assert result[1]["case_id"] == "c2"


def test_save_multiple_cases_each_on_own_line(tmp_path):
    cases = [{"id": i} for i in range(5)]
    path = str(tmp_path / "multi.jsonl")
    save_cases(cases, path)
    lines = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 5
