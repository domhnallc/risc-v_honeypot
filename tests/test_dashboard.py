"""Tests for tools/dashboard.py -- the standalone, read-only HTML report
generator built from the honeypot's own JSONL event logs.

Deliberately kept in tests/ even though the tool itself lives outside
honeypot/ (see that file's module docstring for why): every field this
report renders is 100% attacker-controlled, so escaping it correctly is a
real safety property worth a regression test, not just a nice-to-have.
"""
from __future__ import annotations

import math
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from dashboard import GeoLookup, Report, _render_map, _word_cloud, render_html  # noqa: E402


def _events(*rows):
    return list(rows)


def test_empty_log_renders_without_crashing():
    report = Report([])
    out = render_html(report, GeoLookup(None))
    assert out.startswith("<!doctype html>")
    assert "No data yet." in out or "No login attempts" in out


def test_attacker_controlled_fields_are_escaped():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "session.connect",
         "session_id": "abc123", "src_ip": "1.2.3.4", "protocol": "ssh"},
        {"timestamp": "2026-01-01T00:00:01Z", "event": "command.input",
         "session_id": "abc123", "raw": "<script>alert(1)</script>"},
        {"timestamp": "2026-01-01T00:00:02Z", "event": "login.failed",
         "username": "<img src=x onerror=alert(1)>", "password": 'p"onmouseover=alert(1)'},
        {"timestamp": "2026-01-01T00:00:03Z", "event": "file.download", "outcome": "success",
         "url": "http://evil/<script>pwn()</script>", "requested_filename": "f.bin",
         "size_bytes": 10, "sha256": "a" * 64, "detected_type": "elf"},
    )
    out = render_html(Report(events), GeoLookup(None))
    assert "<script>" not in out
    assert "<img src=x" not in out
    # the raw text is expected to still appear (that's the point of the
    # report), but only ever as an escaped, inert entity -- never as a
    # live tag the browser would parse and execute.
    assert "&lt;img src=x onerror=alert(1)&gt;" in out
    assert "&lt;script&gt;pwn()&lt;/script&gt;" in out


def test_last_ten_commands_ordered_most_recent_first():
    events = [
        {"timestamp": f"2026-01-01T00:00:{i:02d}Z", "event": "command.input",
         "session_id": "s", "raw": f"cmd{i}"}
        for i in range(15)
    ]
    report = Report(events)
    assert [ev["raw"] for ev in report.commands[:3]] == ["cmd14", "cmd13", "cmd12"]
    assert len(report.commands) == 15  # trimming to 10 happens at render time


def test_download_requested_events_are_excluded():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "file.download", "outcome": "requested"},
        {"timestamp": "2026-01-01T00:00:01Z", "event": "file.download", "outcome": "success"},
    )
    report = Report(events)
    assert len(report.downloads) == 1
    assert report.downloads[0]["outcome"] == "success"


def test_geo_unavailable_shows_fallback_and_no_map():
    geo = GeoLookup(None)
    assert not geo.available
    assert geo.lookup("8.8.8.8") is None
    out = render_html(Report([]), geo)
    assert "No GeoIP database configured" in out


def test_word_cloud_empty_and_scaled():
    from collections import Counter
    assert "No entries" in _word_cloud(Counter(), "No entries")
    out = _word_cloud(Counter({"root": 50, "admin": 1}), "empty")
    assert "root" in out and "admin" in out


def test_render_map_produces_valid_svg_with_points():
    svg = _render_map([(-0.1, 51.5, "London", 5), (139.7, 35.7, "Tokyo", 2)])
    assert svg.startswith("<svg")
    assert svg.count("<circle") == 2
    assert "<path" in svg


def test_off_wordlist_logins_are_collected_and_shown():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.failed", "src_ip": "1.2.3.4",
         "username": "zzz_probe", "password": "zzz_probe",
         "username_known": False, "password_known": False},
        {"timestamp": "2026-01-01T00:00:01Z", "event": "login.success", "src_ip": "5.6.7.8",
         "username": "root", "password": "123456",
         "username_known": True, "password_known": True},
    )
    report = Report(events)
    assert len(report.off_list_logins) == 1
    assert report.off_list_logins[0]["username"] == "zzz_probe"
    out = render_html(report, GeoLookup(None))
    assert "zzz_probe" in out
    assert "Credential attempts not on the known wordlist (1)" in out


def test_repeat_visitor_ips_are_identified():
    events = _events(
        # 1.2.3.4 logs in successfully twice -- the harvester-then-loader pattern
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.success", "src_ip": "1.2.3.4", "username": "root"},
        {"timestamp": "2026-01-02T00:00:00Z", "event": "login.success", "src_ip": "1.2.3.4", "username": "admin"},
        # 5.6.7.8 only logs in once -- not a repeat
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.success", "src_ip": "5.6.7.8", "username": "root"},
    )
    report = Report(events)
    assert report.repeat_visitor_ips == [
        ("1.2.3.4", report.successful_logins_by_ip["1.2.3.4"]),
    ]
    out = render_html(report, GeoLookup(None))
    assert "Repeat successful logins (1)" in out
    assert "1.2.3.4" in out
    assert "admin, root" in out  # usernames sorted alphabetically


def test_no_repeat_visitors_shows_explanatory_message():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.success", "src_ip": "5.6.7.8", "username": "root"},
    )
    out = render_html(Report(events), GeoLookup(None))
    assert "Repeat successful logins (0)" in out
    assert "harvester bot" in out


def test_off_wordlist_section_explains_itself_when_not_configured():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.failed", "src_ip": "1.2.3.4",
         "username": "root", "password": "root", "username_known": None, "password_known": None},
    )
    out = render_html(Report(events), GeoLookup(None))
    assert "No username/password wordlist configured" in out


# -- architecture breakdown ---------------------------------------------------------

def _dl(**kw):
    kw.setdefault("event", "file.download")
    kw.setdefault("timestamp", "2026-01-01T00:00:00Z")
    kw.setdefault("outcome", "success")
    kw.setdefault("url", "http://c2/x")
    return kw


def test_arch_family_lumps_endianness_variants_and_names_aarch64_distinctly():
    from dashboard import _arch_family
    mips_be = _dl(detected_type="elf", detected_machine="EM_MIPS")
    mips_le = _dl(detected_type="elf", detected_machine="EM_MIPS_RS3_LE")
    assert _arch_family(mips_be) == _arch_family(mips_le) == "MIPS"      # MIPS vs. MIPSEL: one family
    assert _arch_family(_dl(detected_type="elf", detected_machine="EM_ARM")) == "ARM"
    assert _arch_family(_dl(detected_type="elf", detected_machine="EM_AARCH64")) == "AArch64"  # not lumped with ARM
    assert _arch_family(_dl(detected_type="elf", detected_machine="EM_PPC")) == \
        _arch_family(_dl(detected_type="elf", detected_machine="EM_PPC64")) == "PowerPC"


def test_arch_family_lumps_every_non_elf_type_into_one_bucket():
    """script/unknown/gzip/... aren't CPU architectures -- a different dimension
    this chart isn't about -- so none of them compete for an identity color."""
    from dashboard import _arch_family, _NON_ELF_LABEL
    for detected_type in ("script", "unknown", "gzip", "pe", "zip"):
        assert _arch_family(_dl(detected_type=detected_type)) == _NON_ELF_LABEL


def test_arch_family_names_unmapped_machines_by_their_raw_code():
    from dashboard import _arch_family
    assert _arch_family(_dl(detected_type="elf", detected_machine="EM_UNKNOWN(4)")) == "EM_UNKNOWN(4)"
    assert _arch_family(_dl(detected_type="elf", detected_machine=None)) == "(unknown machine)"


def test_lump_and_cap_orders_known_labels_first_then_alphabetical():
    from collections import Counter
    from dashboard import _lump_and_cap
    counts = Counter({"zebra": 1, "RISC-V": 1, "apple": 1, "ARM": 1})
    assert _lump_and_cap(counts, ["RISC-V", "ARM"]) == [
        ("RISC-V", 1), ("ARM", 1), ("apple", 1), ("zebra", 1)]


def test_lump_and_cap_is_a_no_op_under_the_slice_cap():
    from collections import Counter
    from dashboard import _lump_and_cap
    counts = Counter({"a": 3, "b": 1})
    assert _lump_and_cap(counts, ["a", "b"], max_slices=6) == [("a", 3), ("b", 1)]
    assert _lump_and_cap(Counter(), ["a"]) == []


def test_lump_and_cap_folds_the_smallest_tail_into_other_keeping_the_biggest():
    from collections import Counter
    from dashboard import _lump_and_cap
    counts = Counter({"big": 100, "mid1": 10, "mid2": 9, "mid3": 8, "mid4": 7, "small1": 2, "small2": 1})
    rows = _lump_and_cap(counts, [], max_slices=6)
    assert len(rows) == 6
    kept = dict(rows[:-1])
    assert set(kept) == {"big", "mid1", "mid2", "mid3", "mid4"}   # the 5 biggest, verbatim
    assert rows[-1] == ("Other", 3)                                # small1 + small2 folded together


def test_lump_and_cap_prefers_known_order_over_count_when_tied():
    """Among labels tied on count, one already in the fixed `order` list is kept
    ahead of an unlisted one -- known architectures should not get bumped out of
    their own chart by an obscure unmapped one, on an arbitrary count tie."""
    from collections import Counter
    from dashboard import _lump_and_cap
    counts = Counter({"RISC-V": 5, "ARM": 1, "obscure1": 1, "obscure2": 1,
                      "obscure3": 1, "obscure4": 1, "obscure5": 1})
    rows = _lump_and_cap(counts, ["RISC-V", "ARM"], max_slices=6)
    labels = dict(rows)
    # 7 distinct labels > 6 slices: keep the 5 biggest (RISC-V, then a 6-way count-1
    # tie broken by _lump_and_cap's own ordering -- ARM first since it is listed,
    # then obscure1-3 alphabetically), fold the remaining 2 into Other.
    assert set(labels) == {"RISC-V", "ARM", "obscure1", "obscure2", "obscure3", "Other"}
    assert labels["Other"] == 2  # obscure4 + obscure5, the two NOT kept


# -- color slot stability (see _slot_for_label's own comment for why this matters) ---

def test_slot_for_label_is_stable_regardless_of_which_other_families_are_present():
    """The bug this guards: assigning color by *position* in that render's row list
    meant ARM would inherit RISC-V's blue on a day RISC-V had zero downloads --
    "recolor on filter," just triggered by the data instead of a UI filter."""
    from dashboard import _slot_for_label
    with_riscv = _slot_for_label("ARM")
    without_riscv = _slot_for_label("ARM")   # the function takes no context -- there IS no "without" to pass
    assert with_riscv == without_riscv == "s2"


def test_slot_for_label_never_uses_pythons_salted_hash():
    """Python's hash() of a str is randomized per-process (PYTHONHASHSEED) unless
    disabled -- using it here would repaint the whole chart on every single run."""
    from dashboard import _slot_for_label
    import subprocess, sys
    outputs = {
        subprocess.run([sys.executable, "-c",
                        "import sys; sys.path.insert(0, 'tools'); from dashboard import _slot_for_label; "
                        "print(_slot_for_label('some-unmapped-machine'))"],
                       capture_output=True, text=True, cwd=".").stdout.strip()
        for _ in range(3)
    }
    assert len(outputs) == 1   # same answer every process, not one draw per run


def test_the_8_primary_families_and_8_arm_eabi_buckets_never_collide_with_each_other():
    from dashboard import _FAMILY_SLOT, _ARM_EABI_SLOT, _slot_for_label
    family_slots = [_slot_for_label(l) for l in _FAMILY_SLOT]
    assert len(family_slots) == len(set(family_slots)) == 8
    arm_slots = [_slot_for_label(l) for l in _ARM_EABI_SLOT]
    assert len(arm_slots) == len(set(arm_slots)) == 8


def test_other_and_non_elf_bucket_share_the_neutral_slot_not_an_identity_one():
    from dashboard import _slot_for_label
    assert _slot_for_label("Other") == _slot_for_label("(non-ELF file)") == "other"
    assert "other" not in {_slot_for_label(l) for l in ("RISC-V", "ARM", "AArch64", "MIPS",
                                                        "x86-64", "x86", "PowerPC", "SPARC")}


# -- architecture donut data -----------------------------------------------------------

def test_architecture_donut_lumps_mips_and_mipsel_and_all_non_elf_types_together():
    from dashboard import _architecture_donut
    data = _architecture_donut([
        _dl(sha256="a" * 64, detected_type="elf", detected_machine="EM_MIPS"),
        _dl(sha256="b" * 64, detected_type="elf", detected_machine="EM_MIPS_RS3_LE"),
        _dl(sha256="c" * 64, detected_type="script"),
        _dl(sha256="d" * 64, detected_type="unknown"),
    ])
    counts = dict(data.rows)
    assert counts == {"MIPS": 2, "(non-ELF file)": 2}


def test_architecture_donut_annotates_only_the_family_with_a_persona_judgement():
    """Only RISC-V ever carries arch_mismatch (honeypot/fetcher/elf.py's
    arch_matches_persona judges nothing else) -- this must not leak onto ARM etc."""
    from dashboard import _architecture_donut
    data = _architecture_donut([
        _dl(sha256="a" * 64, detected_type="elf", detected_machine="EM_RISCV", arch_mismatch=False),
        _dl(sha256="b" * 64, detected_type="elf", detected_machine="EM_RISCV", arch_mismatch=False),
        _dl(sha256="c" * 64, detected_type="elf", detected_machine="EM_RISCV", arch_mismatch=True),
        _dl(sha256="d" * 64, detected_type="elf", detected_machine="EM_ARM"),
    ])
    assert data.persona == {"RISC-V": (2, 1), "ARM": (0, 0)}


def test_architecture_donut_ignores_non_success_downloads():
    from dashboard import _architecture_donut
    assert _architecture_donut([
        _dl(outcome="requested"),
        _dl(outcome="failed", error="HTTP 404"),
    ]) is None
    assert _architecture_donut([]) is None


def test_architecture_donut_caps_at_max_slices_with_the_rest_folded():
    from dashboard import _architecture_donut, _MAX_DONUT_SLICES
    families = ["EM_RISCV", "EM_ARM", "EM_MIPS", "EM_X86_64", "EM_386", "EM_PPC", "EM_SPARC", "EM_SH"]
    data = _architecture_donut([
        _dl(sha256=str(i) * 64, detected_type="elf", detected_machine=m) for i, m in enumerate(families)
    ])
    assert len(data.rows) == _MAX_DONUT_SLICES
    assert data.rows[-1][0] == "Other"


# -- ARM EABI-version donut -------------------------------------------------------------

def test_arm_version_donut_buckets_by_eabi_version_only_arm_downloads_counted():
    from dashboard import _arm_version_donut
    data = _arm_version_donut([
        _dl(sha256="a" * 64, detected_type="elf", detected_machine="EM_ARM", detected_abi="EABI5 hard-float"),
        _dl(sha256="b" * 64, detected_type="elf", detected_machine="EM_ARM", detected_abi="EABI5 soft-float"),
        _dl(sha256="c" * 64, detected_type="elf", detected_machine="EM_ARM", detected_abi="pre-EABI"),
        _dl(sha256="d" * 64, detected_type="elf", detected_machine="EM_ARM", detected_abi=None),
        _dl(sha256="e" * 64, detected_type="elf", detected_machine="EM_X86_64"),   # not ARM: excluded
    ])
    assert dict(data.rows) == {"EABI5": 2, "pre-EABI": 1, "unknown": 1}


def test_arm_version_donut_is_none_when_there_are_no_arm_downloads():
    from dashboard import _arm_version_donut
    assert _arm_version_donut([_dl(detected_type="elf", detected_machine="EM_X86_64")]) is None
    assert _arm_version_donut([]) is None


# -- donut SVG rendering -----------------------------------------------------------------

def test_donut_svg_shows_every_label_count_and_percentage_as_real_text():
    """The legend carries exact numbers as text, not just arc geometry -- nothing
    here is hover-only."""
    from dashboard import _DonutData, _donut_svg
    out = _donut_svg(_DonutData([("RISC-V", 3), ("ARM", 1)], {}), "downloads", "donut-test")
    assert "RISC-V" in out and "3" in out and "75%" in out
    assert "ARM" in out and "25%" in out
    assert out.count("<circle") == 2
    assert "id='donut-test'" in out


def test_donut_svg_shows_match_and_mismatch_as_status_text_not_recolored_arcs():
    from dashboard import _DonutData, _donut_svg
    out = _donut_svg(_DonutData([("RISC-V", 3)], {"RISC-V": (2, 1)}), "downloads", "d")
    assert "2 match" in out and "1 mismatch" in out
    assert "donut-match" in out and "donut-mismatch" in out


def test_donut_svg_arcs_sum_to_the_full_circumference_minus_gaps():
    """Geometry check: every arc's dash length plus every gap must reconstruct the
    whole ring, or a slice's true proportion wouldn't match what's drawn."""
    import math
    from dashboard import _DonutData, _donut_svg, _DONUT_GAP_PX
    rows = [("a", 5), ("b", 3), ("c", 2)]
    out = _donut_svg(_DonutData(rows, {}), "x", "d")
    dashes = [float(m.group(1)) for m in re.finditer(r"stroke-dasharray='([\d.]+) ", out)]
    assert len(dashes) == 3
    r = (148 - 26) / 2
    circumference = 2 * math.pi * r
    assert sum(dashes) == pytest.approx(circumference - _DONUT_GAP_PX * len(rows), abs=0.5)


def test_donut_svg_single_slice_has_no_gap():
    from dashboard import _DonutData, _donut_svg
    out = _donut_svg(_DonutData([("RISC-V", 1)], {}), "x", "d")
    dash = float(re.search(r"stroke-dasharray='([\d.]+) ", out).group(1))
    r = (148 - 26) / 2
    assert dash == pytest.approx(2 * math.pi * r, abs=0.01)   # the full ring, no gap subtracted


def test_donut_svg_empty_for_no_rows_or_zero_total():
    from dashboard import _DonutData, _donut_svg
    assert "No data yet." in _donut_svg(_DonutData([], {}), "x", "d")
    assert "No data yet." in _donut_svg(_DonutData([("a", 0)], {}), "x", "d")


def test_donut_svg_labels_are_escaped():
    from dashboard import _DonutData, _donut_svg
    out = _donut_svg(_DonutData([("<script>pwn()</script>", 1)], {}), "x", "d")
    assert "<script>pwn()</script>" not in out
    assert "&lt;script&gt;pwn()&lt;/script&gt;" in out


# -- failure-reason breakdown --------------------------------------------------------

def test_failure_reason_buckets_by_type_not_by_literal_url_or_message():
    from dashboard import _failure_reason
    assert _failure_reason("HTTP 404") == "HTTP 404"
    assert _failure_reason("HTTP 500") == "HTTP 500"
    assert _failure_reason("blocked non-public destination: 169.254.169.254 is link-local") == \
        "blocked: non-public destination (SSRF guard)"
    assert _failure_reason("protocol 'tftp' not permitted by fetcher config") == \
        "protocol not permitted (fetcher.allowed_protocols)"
    assert _failure_reason("protocol 'tftp' not yet implemented") == "protocol not implemented (tftp/ftp)"
    assert _failure_reason("payload exceeded max_file_size_bytes (52428800)") == \
        "oversized transfer (max_file_size_bytes)"
    assert _failure_reason("per-session download limit reached") == "per-session download limit reached"
    assert _failure_reason("timed out waiting for isolated fetcher") == \
        "isolated fetcher did not respond (queued mode)"
    assert _failure_reason(None) == "(unknown)"


def test_failure_reason_truncates_long_unrecognised_errors():
    from dashboard import _failure_reason
    long_error = "Cannot connect to host " + "a" * 100
    reason = _failure_reason(long_error)
    assert len(reason) <= 83 and reason.endswith("...")


def test_failure_breakdown_groups_counts_and_flags_stage2():
    from dashboard import _failure_breakdown
    rows = _failure_breakdown([
        _dl(outcome="failed", error="HTTP 404"),
        _dl(outcome="failed", error="HTTP 404"),
        _dl(outcome="failed", error="HTTP 404", stage=2),
        _dl(outcome="failed", error="protocol 'tftp' not permitted by fetcher config"),
        _dl(outcome="success"),   # excluded: not a failure
    ])
    assert rows[0] == ["HTTP 404", "3", "1"]
    assert ["protocol not permitted (fetcher.allowed_protocols)", "1", "-"] in rows


def test_architecture_and_failure_sections_appear_in_the_rendered_page():
    events = _events(
        _dl(detected_type="elf", detected_machine="EM_RISCV", detected_bitness=64,
            detected_endianness="little", detected_abi="RVC double-float",
            arch_mismatch=False, sha256="a" * 64, stage=2),
        _dl(detected_type="elf", detected_machine="EM_ARM", detected_abi="EABI5 hard-float", sha256="b" * 64),
        _dl(outcome="failed", error="HTTP 404"),
    )
    out = render_html(Report(events), GeoLookup(None))
    assert "Downloads by architecture" in out and "RISC-V" in out and "&check; 1 match" in out
    assert "ARM builds by EABI version" in out and "EABI5" in out
    assert "Failed downloads by reason" in out and "HTTP 404" in out
    assert "<div class='n'>1</div><div class='l'>Stage-2 downloads</div>" in out   # not just the label


def test_arm_section_is_omitted_when_there_are_no_arm_downloads():
    events = _events(_dl(detected_type="elf", detected_machine="EM_RISCV", arch_mismatch=False, sha256="a" * 64))
    out = render_html(Report(events), GeoLookup(None))
    assert "ARM builds by EABI version" not in out


def test_architecture_and_failure_error_text_is_escaped():
    events = _events(_dl(outcome="failed", error="Cannot connect to <script>pwn()</script>"))
    out = render_html(Report(events), GeoLookup(None))
    assert "<script>pwn()</script>" not in out
    assert "&lt;script&gt;pwn()&lt;/script&gt;" in out


def test_empty_architecture_and_failure_sections_show_fallback_text():
    out = render_html(Report([]), GeoLookup(None))
    assert "No successful downloads yet." in out
