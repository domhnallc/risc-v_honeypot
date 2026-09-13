"""Tests for tools/dashboard_server.py -- the live Flask version of
tools/dashboard.py's report.

Kept light: the report content itself (aggregation, escaping, rendering)
is already covered by test_dashboard.py against the shared dashboard.py
module this just serves dynamically. These tests only cover the serving
behavior specific to this file: the route responds, it reflects the
current file content on each request (not a stale cached copy), and the
auto-refresh tag is injected as configured.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("flask")  # only in the optional `dashboard-server` extra

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import dashboard_server  # noqa: E402
from dashboard import GeoLookup  # noqa: E402


def _client(tmp_path, events_text="", refresh_seconds=15):
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(events_text)
    dashboard_server._events_path = events_path
    dashboard_server._geo = GeoLookup(None)
    dashboard_server._refresh_seconds = refresh_seconds
    return dashboard_server.app.test_client()


def test_index_returns_the_dashboard_html(tmp_path):
    client = _client(tmp_path)
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"RISC-V Honeypot Dashboard" in resp.data


def test_index_reflects_current_file_content_each_request(tmp_path):
    client = _client(tmp_path, events_text="")
    first = client.get("/").data
    assert b"zzz_new_visitor_ip" not in first

    (tmp_path / "events.jsonl").write_text(
        '{"timestamp": "2026-01-01T00:00:00Z", "event": "session.connect", '
        '"session_id": "s1", "src_ip": "zzz_new_visitor_ip", "protocol": "ssh"}\n'
    )
    second = client.get("/").data
    assert b"zzz_new_visitor_ip" in second


def test_refresh_meta_tag_is_injected_when_enabled(tmp_path):
    client = _client(tmp_path, refresh_seconds=30)
    resp = client.get("/")
    assert b'<meta http-equiv="refresh" content="30">' in resp.data


def test_refresh_meta_tag_is_absent_when_disabled(tmp_path):
    client = _client(tmp_path, refresh_seconds=0)
    resp = client.get("/")
    assert b"http-equiv=\"refresh\"" not in resp.data
