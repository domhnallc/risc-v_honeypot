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
