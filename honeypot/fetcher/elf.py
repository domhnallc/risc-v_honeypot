"""Static, read-only file-type / architecture detection.

Hand-rolled rather than shelling out to `file` or invoking any library that
maps/loads the sample -- spec sec 2.5 requires detection that never executes
or partially loads the sample. This only ever reads raw bytes and compares
them against known magic numbers / a fixed-offset header layout.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

EM_RISCV = 243
# e_machine values seen in IoT/embedded malware and Linux userland generally
# (a captured dropper served m68k, MIPS, PowerPC, SuperH, SPARC and x86-64
# builds side by side). Anything not listed is reported as EM_UNKNOWN(n)
# rather than guessed at.
_EM_NAMES = {
    2: "EM_SPARC",
    3: "EM_386",
    4: "EM_68K",
    8: "EM_MIPS",
    10: "EM_MIPS_RS3_LE",
    15: "EM_PARISC",
    18: "EM_SPARC32PLUS",
    20: "EM_PPC",
    21: "EM_PPC64",
    22: "EM_S390",
    40: "EM_ARM",
    42: "EM_SH",
    43: "EM_SPARCV9",
    50: "EM_IA_64",
    62: "EM_X86_64",
    92: "EM_OPENRISC",
    93: "EM_ARC_COMPACT",
    94: "EM_XTENSA",
    113: "EM_NIOS2",
    183: "EM_AARCH64",
    189: "EM_MICROBLAZE",
    195: "EM_ARC_COMPACT2",
    EM_RISCV: "EM_RISCV",
    252: "EM_CSKY",
    258: "EM_LOONGARCH",
}

_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "pe"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"#!", "script"),
]


@dataclass
class DetectedType:
    file_type: str
    is_elf: bool
    bitness: int | None = None
    machine: str | None = None
    endianness: str | None = None
    # Raw e_flags word from the header, and a human decoding of it where the
    # meaning is well defined (see _decode_flags). The decoding is deliberately
    # partial: e_flags does NOT carry an ARM CPU architecture level (v5/v6/v7 is
    # in a section this parser never walks), so it separates ARM builds only by
    # EABI version and float ABI.
    flags: int | None = None
    abi: str | None = None


def detect(data: bytes) -> DetectedType:
    if data[:4] == b"\x7fELF":
        return _parse_elf_header(data)
    for sig, name in _MAGIC_SIGNATURES:
        if data.startswith(sig):
            return DetectedType(file_type=name, is_elf=False)
    return DetectedType(file_type="unknown", is_elf=False)


def _parse_elf_header(data: bytes) -> DetectedType:
    """Parse only the fixed-size ELF identification + header fields.

    Reads e_ident/e_machine straight out of the byte buffer with
    struct.unpack -- no section/segment walking, no mmap, no loader
    involvement of any kind.
    """
    if len(data) < 20:
        return DetectedType(file_type="elf", is_elf=True)
    ei_class = data[4]  # 1 = ELFCLASS32, 2 = ELFCLASS64
    ei_data = data[5]   # 1 = little-endian, 2 = big-endian
    bitness = {1: 32, 2: 64}.get(ei_class)
    endianness = {1: "little", 2: "big"}.get(ei_data)
    fmt_endian = "<" if ei_data == 1 else ">"
    machine = None
    try:
        e_machine = struct.unpack_from(f"{fmt_endian}H", data, 18)[0]
        machine = _EM_NAMES.get(e_machine, f"EM_UNKNOWN({e_machine})")
    except struct.error:
        pass
    flags = None
    flags_offset = {1: 36, 2: 48}.get(ei_class)   # e_flags follows e_entry/e_phoff/e_shoff, which are 4 or 8 bytes each
    if flags_offset is not None:
        try:
            flags = struct.unpack_from(f"{fmt_endian}I", data, flags_offset)[0]
        except struct.error:
            pass
    return DetectedType(
        file_type="elf", is_elf=True, bitness=bitness,
        machine=machine, endianness=endianness,
        flags=flags, abi=_decode_flags(machine, flags, bitness),
    )


_MIPS_ARCH = {
    0x00000000: "MIPS-I", 0x10000000: "MIPS-II", 0x20000000: "MIPS-III", 0x30000000: "MIPS-IV",
    0x40000000: "MIPS-V", 0x50000000: "MIPS32", 0x60000000: "MIPS64", 0x70000000: "MIPS32r2",
    0x80000000: "MIPS64r2", 0x90000000: "MIPS32r6", 0xA0000000: "MIPS64r6",
}
_MIPS_ABI = {0x1000: "o32", 0x2000: "o64", 0x3000: "eabi32", 0x4000: "eabi64"}
_RISCV_FLOAT_ABI = {0: "soft-float", 2: "single-float", 4: "double-float", 6: "quad-float"}
# EF_SH_MACH_MASK (0x1f) values, with the names GNU readelf prints for them --
# checked against readelf itself rather than trusted from memory.
_SH_MACH = {
    0x01: "sh1", 0x02: "sh2", 0x03: "sh3", 0x04: "sh-dsp", 0x05: "sh3-dsp", 0x06: "sh4al-dsp",
    0x08: "sh3e", 0x09: "sh4", 0x0A: "sh5", 0x0B: "sh2e", 0x0C: "sh4a", 0x0D: "sh2a",
    0x10: "sh4-nofpu", 0x11: "sh4a-nofpu", 0x12: "sh4-nommu-nofpu", 0x13: "sh2a-nofpu",
    0x14: "sh3-nommu", 0x15: "sh2a-nofpu-or-sh4-nommu-nofpu", 0x16: "sh2a-nofpu-or-sh3-nommu",
    0x17: "sh2a-or-sh4", 0x18: "sh2a-or-sh3e",
}


def _decode_flags(machine: str | None, flags: int | None, bitness: int | None) -> str | None:
    """Human reading of e_flags for the machines where the layout is certain.

    Anything else returns None and the raw value is still recorded -- a wrong
    decoding is worse than none, so PowerPC, SPARC and 68k are left raw.
    """
    if flags is None:
        return None
    if machine == "EM_ARM":
        eabi = flags >> 24
        parts = [f"EABI{eabi}" if eabi else "pre-EABI"]
        if flags & 0x400:
            parts.append("hard-float")
        elif flags & 0x200:
            parts.append("soft-float")
        if flags & 0x00800000:
            parts.append("BE8")
        return " ".join(parts)
    if machine in ("EM_MIPS", "EM_MIPS_RS3_LE"):
        arch = _MIPS_ARCH.get(flags & 0xF0000000, "MIPS?")
        abi = _MIPS_ABI.get(flags & 0x0000F000)
        if abi is None and flags & 0x00000020:      # EF_MIPS_ABI2
            abi = "n32"
        return f"{arch} {abi}" if abi else arch
    if machine == "EM_SH":
        return _SH_MACH.get(flags & 0x1F)
    if machine == "EM_RISCV":
        parts = []
        if flags & 0x1:
            parts.append("RVC")
        parts.append(_RISCV_FLOAT_ABI[flags & 0x6])
        if flags & 0x8:
            parts.append("RVE")
        if flags & 0x10:
            parts.append("TSO")
        return " ".join(parts)
    return None


def arch_matches_persona(detected: DetectedType, persona_arch: str) -> bool | None:
    """Returns None when we can't judge (not ELF / not RISC-V), else bool.

    A mismatch (dropper serving the wrong arch) is itself interesting signal
    per spec sec 4.4 step 6, not just noise to filter out.
    """
    if not detected.is_elf or detected.machine != "EM_RISCV":
        return None
    expected_bits = 64 if persona_arch == "riscv64" else 32
    return detected.bitness == expected_bits
