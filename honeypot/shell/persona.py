"""Renders config-driven fake device output (spec sec 4.2).

Every string here is built from trusted config values only (never from
attacker input), so plain str.format/f-strings are safe -- there is no path
by which attacker-controlled text reaches a template here.
"""
from __future__ import annotations

from honeypot.config.schema import PersonaConfig

_BUSYBOX_APPLETS = [
    "sh", "ash", "cat", "ls", "cp", "mv", "rm", "mkdir", "touch", "echo",
    "ps", "wget", "tftp", "chmod", "grep", "sed", "awk", "ifconfig", "ping",
    "top", "vi", "reboot", "mount", "ip",
]


def uname_a(persona: PersonaConfig) -> str:
    machine = "riscv64" if persona.arch == "riscv64" else "riscv32"
    return (
        f"Linux {persona.hostname} {persona.kernel_version} "
        f"#1 SMP PREEMPT {machine} GNU/Linux"
    )


def uname_m(persona: PersonaConfig) -> str:
    return "riscv64" if persona.arch == "riscv64" else "riscv32"


def proc_cpuinfo(persona: PersonaConfig) -> str:
    blocks = []
    for hart in range(persona.hart_count):
        blocks.append(
            f"processor\t: {hart}\n"
            f"hart\t\t: {hart}\n"
            f"isa\t\t: {persona.isa}\n"
            f"mmu\t\t: {persona.mmu}\n"
            f"uarch\t\t: {persona.uarch}\n"
        )
    return "\n".join(blocks)


def proc_version(persona: PersonaConfig) -> str:
    return (
        f"Linux version {persona.kernel_version} "
        f"(buildroot@buildroot) (gcc version 10.3.0) "
        f"#1 SMP PREEMPT"
    )


def etc_os_release(persona: PersonaConfig) -> str:
    return (
        f'NAME="{persona.os_release_name}"\n'
        f'VERSION="{persona.os_release_version}"\n'
        f'ID={persona.os_release_name.lower()}\n'
        f'VERSION_ID="{persona.os_release_version}"\n'
        f'PRETTY_NAME="{persona.os_release_name} {persona.os_release_version}"\n'
    )


def bin_listing() -> list[str]:
    return sorted(set(_BUSYBOX_APPLETS))


def login_banner(persona: PersonaConfig) -> str:
    return persona.telnet_banner


def ssh_banner(persona: PersonaConfig) -> str:
    return persona.ssh_banner
