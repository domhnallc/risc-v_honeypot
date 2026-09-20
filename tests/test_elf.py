"""Tests for the static ELF/file-type detector (honeypot/fetcher/elf.py).

The detector must never execute or load its input -- these tests build
synthetic byte buffers by hand (no real binaries involved) to prove the
parser works from raw bytes alone.
"""
from __future__ import annotations

import struct

from honeypot.fetcher import elf


def _make_elf_header(*, ei_class: int, ei_data: int, e_machine: int) -> bytes:
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = ei_class
    ident[5] = ei_data
    ident[6] = 1  # EI_VERSION
    endian = "<" if ei_data == 1 else ">"
    e_type = 2  # ET_EXEC
    rest = struct.pack(f"{endian}HH", e_type, e_machine)
    return bytes(ident) + rest


def test_detects_elf64_riscv_little_endian():
    header = _make_elf_header(ei_class=2, ei_data=1, e_machine=elf.EM_RISCV)
    detected = elf.detect(header)
    assert detected.is_elf
    assert detected.bitness == 64
    assert detected.machine == "EM_RISCV"
    assert detected.endianness == "little"


def test_detects_elf32_riscv():
    header = _make_elf_header(ei_class=1, ei_data=1, e_machine=elf.EM_RISCV)
    detected = elf.detect(header)
    assert detected.bitness == 32
    assert detected.machine == "EM_RISCV"


def test_non_riscv_machine_is_not_judged_as_mismatch():
    """A non-RISC-V binary isn't a same-arch "mismatch" -- it's simply
    inapplicable to compare against a RISC-V persona, so arch_matches_persona
    returns None (see honeypot/fetcher/elf.py) rather than False."""
    header = _make_elf_header(ei_class=2, ei_data=1, e_machine=62)  # EM_X86_64
    detected = elf.detect(header)
    assert detected.machine == "EM_X86_64"
    assert elf.arch_matches_persona(detected, "riscv64") is None


def test_arch_match_true_for_matching_riscv64():
    header = _make_elf_header(ei_class=2, ei_data=1, e_machine=elf.EM_RISCV)
    detected = elf.detect(header)
    assert elf.arch_matches_persona(detected, "riscv64") is True


def test_arch_mismatch_for_riscv32_payload_on_riscv64_persona():
    header = _make_elf_header(ei_class=1, ei_data=1, e_machine=elf.EM_RISCV)
    detected = elf.detect(header)
    assert elf.arch_matches_persona(detected, "riscv64") is False


def test_non_elf_gzip_magic():
    detected = elf.detect(b"\x1f\x8b\x08\x00")
    assert not detected.is_elf
    assert detected.file_type == "gzip"


def test_shebang_script_detected():
    detected = elf.detect(b"#!/bin/sh\necho hi\n")
    assert detected.file_type == "script"
    assert not detected.is_elf


def test_unknown_bytes():
    detected = elf.detect(b"\x00\x01\x02\x03")
    assert detected.file_type == "unknown"


def test_arch_matches_persona_returns_none_for_non_elf():
    detected = elf.detect(b"\x1f\x8b")
    assert elf.arch_matches_persona(detected, "riscv64") is None


def test_names_the_architectures_seen_in_iot_dropper_kits():
    # Straight from a captured dropper that served one build per name:
    # m68k, MIPS, PowerPC, SuperH, SPARC and x86-64, all 32-bit except the last.
    expected = {4: "EM_68K", 8: "EM_MIPS", 20: "EM_PPC", 42: "EM_SH", 2: "EM_SPARC", 62: "EM_X86_64"}
    for e_machine, name in expected.items():
        detected = elf.detect(_make_elf_header(ei_class=1, ei_data=2, e_machine=e_machine))
        assert detected.machine == name, e_machine


def test_unlisted_machines_are_reported_as_unknown_not_guessed():
    detected = elf.detect(_make_elf_header(ei_class=1, ei_data=1, e_machine=9999))
    assert detected.machine == "EM_UNKNOWN(9999)"


def test_endianness_distinguishes_mips_from_mipsel():
    be = elf.detect(_make_elf_header(ei_class=1, ei_data=2, e_machine=8))
    le = elf.detect(_make_elf_header(ei_class=1, ei_data=1, e_machine=8))
    assert (be.machine, be.endianness) == ("EM_MIPS", "big")
    assert (le.machine, le.endianness) == ("EM_MIPS", "little")


# -- e_flags ---------------------------------------------------------------------

def _full_header(*, ei_class: int, ei_data: int, e_machine: int, e_flags: int) -> bytes:
    """A complete ELF header (52 bytes for ELFCLASS32, 64 for ELFCLASS64) with e_flags
    at its real offset: 36 after three 4-byte fields, 48 after three 8-byte ones."""
    endian = "<" if ei_data == 1 else ">"
    ident = bytes([0x7F, 0x45, 0x4C, 0x46, ei_class, ei_data, 1]) + bytes(9)
    if ei_class == 1:
        rest = struct.pack(f"{endian}HHIIIIIHHHHHH", 2, e_machine, 1, 0, 0, 0, e_flags, 52, 32, 0, 40, 0, 0)
    else:
        rest = struct.pack(f"{endian}HHIQQQIHHHHHH", 2, e_machine, 1, 0, 0, 0, e_flags, 64, 56, 0, 64, 0, 0)
    return ident + rest


def _flags(**kw):
    detected = elf.detect(_full_header(**kw))
    return detected.flags, detected.abi


def test_header_builder_matches_the_documented_sizes_and_offsets():
    assert len(_full_header(ei_class=1, ei_data=1, e_machine=40, e_flags=0)) == 52
    assert len(_full_header(ei_class=2, ei_data=1, e_machine=62, e_flags=0)) == 64
    assert _full_header(ei_class=1, ei_data=1, e_machine=40, e_flags=0xAABBCCDD)[36:40] == bytes.fromhex("ddccbbaa")
    assert _full_header(ei_class=2, ei_data=2, e_machine=21, e_flags=0xAABBCCDD)[48:52] == bytes.fromhex("aabbccdd")


def test_arm_flags_give_eabi_version_and_float_abi_only():
    arm = dict(ei_class=1, ei_data=1, e_machine=40)
    assert _flags(**arm, e_flags=0x05000400) == (0x05000400, "EABI5 hard-float")
    assert _flags(**arm, e_flags=0x05000200) == (0x05000200, "EABI5 soft-float")
    assert _flags(**arm, e_flags=0x05000000)[1] == "EABI5"
    assert _flags(**arm, e_flags=0x05800000)[1] == "EABI5 BE8"
    assert _flags(**arm, e_flags=0x00000002)[1] == "pre-EABI"      # old toolchains: no EABI version at all


def test_mips_flags_give_isa_and_abi():
    mips = dict(ei_class=1, ei_data=2, e_machine=8)
    assert _flags(**mips, e_flags=0x50001007)[1] == "MIPS32 o32"
    assert _flags(**mips, e_flags=0x00001007)[1] == "MIPS-I o32"
    assert _flags(**mips, e_flags=0x70001000)[1] == "MIPS32r2 o32"
    assert _flags(**mips, e_flags=0x60000020)[1] == "MIPS64 n32"
    assert _flags(**mips, e_flags=0x70000000)[1] == "MIPS32r2"


def test_riscv_flags_show_compressed_and_float_abi():
    """The one that matters to this project: does a sample match the persona's rv64imafdc?"""
    rv = dict(ei_class=2, ei_data=1, e_machine=243)
    assert _flags(**rv, e_flags=0x5)[1] == "RVC double-float"
    assert _flags(**rv, e_flags=0x0)[1] == "soft-float"
    assert _flags(**rv, e_flags=0x3)[1] == "RVC single-float"
    assert _flags(**rv, e_flags=0x9)[1] == "RVC soft-float RVE"
    assert _flags(**rv, e_flags=0x7)[1] == "RVC quad-float"


def test_other_machines_keep_the_raw_word_but_are_not_decoded():
    assert _flags(ei_class=1, ei_data=2, e_machine=20, e_flags=0x0) == (0x0, None)       # PowerPC
    assert _flags(ei_class=2, ei_data=1, e_machine=62, e_flags=0x0) == (0x0, None)       # x86-64


def test_64_bit_flags_are_read_from_the_64_bit_offset():
    assert _flags(ei_class=2, ei_data=2, e_machine=21, e_flags=0x2)[0] == 0x2            # PPC64, big-endian


def test_a_truncated_header_has_no_flags_but_still_names_the_machine():
    detected = elf.detect(_full_header(ei_class=1, ei_data=1, e_machine=40, e_flags=0x05000400)[:30])
    assert detected.machine == "EM_ARM" and detected.flags is None and detected.abi is None


def test_non_elf_files_have_no_flags():
    detected = elf.detect(b"#!/bin/sh\n")
    assert detected.flags is None and detected.abi is None


def test_superh_flags_name_the_cpu_and_unknown_values_stay_raw():
    sh = dict(ei_class=1, ei_data=2, e_machine=42)
    assert _flags(**sh, e_flags=0x9) == (0x9, "sh4")
    assert _flags(**sh, e_flags=0xC)[1] == "sh4a"
    assert _flags(**sh, e_flags=0x12)[1] == "sh4-nommu-nofpu"
    assert _flags(**sh, e_flags=0x7) == (0x7, None)                # a value readelf calls "unknown ISA"


def test_flags_decoding_agrees_with_gnu_readelf(tmp_path):
    """Cross-check against binutils, which decodes e_flags independently of this
    code. Reads header bytes we synthesise here; nothing is executed. Skipped where
    readelf isn't installed."""
    import shutil
    import subprocess

    import pytest
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf (binutils) not installed")

    cases = [   # (header kwargs, tokens readelf must print, expected decoding here)
        (dict(ei_class=1, ei_data=1, e_machine=40, e_flags=0x05000400), ["Version5 EABI", "hard-float"], "EABI5 hard-float"),
        (dict(ei_class=1, ei_data=1, e_machine=40, e_flags=0x05000200), ["Version5 EABI", "soft-float"], "EABI5 soft-float"),
        (dict(ei_class=1, ei_data=2, e_machine=8, e_flags=0x50001007), ["o32", "mips32"], "MIPS32 o32"),
        (dict(ei_class=1, ei_data=2, e_machine=8, e_flags=0x00001007), ["o32", "mips1"], "MIPS-I o32"),
        (dict(ei_class=1, ei_data=2, e_machine=8, e_flags=0x60000020), ["abi2", "mips64"], "MIPS64 n32"),
        (dict(ei_class=2, ei_data=1, e_machine=243, e_flags=0x5), ["RVC", "double-float"], "RVC double-float"),
        (dict(ei_class=2, ei_data=1, e_machine=243, e_flags=0x3), ["RVC", "single-float"], "RVC single-float"),
        (dict(ei_class=1, ei_data=2, e_machine=42, e_flags=0x9), ["sh4"], "sh4"),
        (dict(ei_class=1, ei_data=2, e_machine=42, e_flags=0xC), ["sh4a"], "sh4a"),
    ]
    for kwargs, tokens, expected in cases:
        path = tmp_path / "header.bin"
        path.write_bytes(_full_header(**kwargs))
        out = subprocess.run([readelf, "-h", str(path)], capture_output=True, text=True).stdout
        flags_line = next(l for l in out.splitlines() if l.strip().startswith("Flags:"))
        assert f"{kwargs['e_flags']:#x}" in flags_line, flags_line          # same word, so the offset is right
        assert all(t in flags_line for t in tokens), (flags_line, tokens)
        assert elf.detect(_full_header(**kwargs)).abi == expected
