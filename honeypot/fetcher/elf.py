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
    return DetectedType(
        file_type="elf", is_elf=True, bitness=bitness,
        machine=machine, endianness=endianness,
    )


def arch_matches_persona(detected: DetectedType, persona_arch: str) -> bool | None:
    """Returns None when we can't judge (not ELF / not RISC-V), else bool.

    A mismatch (dropper serving the wrong arch) is itself interesting signal
    per spec sec 4.4 step 6, not just noise to filter out.
    """
    if not detected.is_elf or detected.machine != "EM_RISCV":
        return None
    expected_bits = 64 if persona_arch == "riscv64" else 32
    return detected.bitness == expected_bits
