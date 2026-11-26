"""Tests for the JSON Lines writer. tmp_path is a pytest-provided temporary folder,
so tests never touch the real data/ directory."""

import json

from pipeline.output import write_jsonl


def read_lines(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def test_writes_one_json_object_per_line(tmp_path):
    out = tmp_path / "alerts.jsonl"
    alerts = [{"alert_id": "1"}, {"alert_id": "2"}, {"alert_id": "3"}]

    count = write_jsonl(alerts, out)

    assert count == 3
    assert read_lines(out) == alerts


def test_rerun_overwrites_instead_of_appending(tmp_path):
    out = tmp_path / "alerts.jsonl"
    write_jsonl([{"alert_id": "old"}], out)
    write_jsonl([{"alert_id": "new"}], out)

    assert read_lines(out) == [{"alert_id": "new"}]


def test_creates_missing_folders(tmp_path):
    out = tmp_path / "does" / "not" / "exist" / "alerts.jsonl"
    write_jsonl([{"alert_id": "1"}], out)
    assert out.exists()


def test_non_english_text_round_trips(tmp_path):
    out = tmp_path / "alerts.jsonl"
    alerts = [{"user": "josé", "raw_log": "Ошибка входа"}]
    write_jsonl(alerts, out)
    assert read_lines(out) == alerts
