"""A per-session in-memory fake filesystem.

Everything here is a plain Python dict tree held in process memory -- there
is no path from any operation in this module to the real host filesystem
(other than the read-only, config-seeded content it's built from), which is
what makes cd/ls/cat/mkdir/rm/touch/echo safe to let an attacker drive freely.
"""
from __future__ import annotations

import random
from copy import deepcopy
from dataclasses import dataclass, field

from honeypot.config.schema import PersonaConfig
from honeypot.shell import persona as persona_render

# A naive fake filesystem showing e.g. "[busybox applet]" for `cat /bin/ls`
# is a one-command giveaway -- real dropper scripts routinely cat/hash /bin
# binaries before trusting a host. This is a deterministic, terminal-safe
# stand-in for real ELF bytes (an ELF magic prefix + pseudo-random low-ASCII
# control characters, never NUL/newline so it can't confuse splitlines()-
# based commands or embed literal zero bytes): it looks like garbled binary
# content rather than empty placeholder text. Generated once per process
# (not per session) because a real binary's bytes don't change between
# reboots of the same device either -- if this varied per session, hashing
# it twice would itself be a tell.
_BUSYBOX_SIZE_BYTES = 934128  # typical size of a static-linked BusyBox build on a small embedded target
_BUSYBOX_SAMPLE_BYTES = 4096  # enough to look like real binary content when cat'd; the full size is only used for ls -l's size column
_busybox_sample_cache: str | None = None


def _busybox_binary_sample() -> str:
    global _busybox_sample_cache
    if _busybox_sample_cache is None:
        rng = random.Random(b"riscv-honeypot-busybox-sample-v1")
        pool = bytes(b for b in range(1, 0x80) if b not in (0x0A, 0x00))
        body = bytes(rng.choice(pool) for _ in range(_BUSYBOX_SAMPLE_BYTES - 4))
        _busybox_sample_cache = "\x7fELF" + body.decode("ascii")
    return _busybox_sample_cache


@dataclass
class FakeFile:
    content: str = ""
    # Lets a file display a realistic ls -l size without actually storing
    # that many characters (see _busybox_binary_sample above). None means
    # "just use len(content)".
    size_override: int | None = None


@dataclass
class FakeSymlink:
    """A real BusyBox install has one real ELF (busybox) with every applet
    name symlinked to it -- `cat`/`ls -l` on an applet should show the
    *target's* content/a symlink line, not its own separate fake file. Only
    resolved one level, within the same parent directory, which is all the
    symlinks this codebase creates need."""
    target: str


@dataclass
class FakeDir:
    entries: dict[str, "FakeDir | FakeFile | FakeSymlink"] = field(default_factory=dict)


class FakeFilesystem:
    """Minimal directory tree, seeded per-persona, navigable with cd/ls/pwd."""

    def __init__(self, persona: PersonaConfig) -> None:
        self.persona = persona
        self.root = FakeDir()
        self._seed()
        self.cwd_path: list[str] = ["root"]

    def _mkdirs(self, *parts: str) -> FakeDir:
        node = self.root
        for part in parts:
            nxt = node.entries.get(part)
            if not isinstance(nxt, FakeDir):
                nxt = FakeDir()
                node.entries[part] = nxt
            node = nxt
        return node

    def _seed(self) -> None:
        bin_dir = self._mkdirs("bin")
        bin_dir.entries.setdefault(
            "busybox", FakeFile(_busybox_binary_sample(), size_override=_BUSYBOX_SIZE_BYTES)
        )
        for applet in persona_render.bin_listing():
            bin_dir.entries.setdefault(applet, FakeSymlink("busybox"))
        self._mkdirs("usr", "bin")

        proc_dir = self._mkdirs("proc")
        proc_dir.entries["cpuinfo"] = FakeFile(persona_render.proc_cpuinfo(self.persona))
        proc_dir.entries["version"] = FakeFile(persona_render.proc_version(self.persona))

        etc_dir = self._mkdirs("etc")
        etc_dir.entries["os-release"] = FakeFile(persona_render.etc_os_release(self.persona))
        etc_dir.entries["passwd"] = FakeFile("root:x:0:0:root:/root:/bin/sh\n")

        self._mkdirs("root")
        self._mkdirs("tmp")
        self._mkdirs("var", "run")

    def _resolve(self, path: str, from_dir: list[str] | None = None) -> list[str]:
        base = list(from_dir if from_dir is not None else self.cwd_path)
        if path.startswith("/"):
            base = ["root"] if path in ("", "/") else []
            parts = path.strip("/").split("/")
        else:
            parts = path.split("/")
        for part in parts:
            if part in ("", "."):
                continue
            if part == "..":
                if len(base) > 1 or (base and base != ["root"]):
                    base = base[:-1] if base != ["root"] else base
            else:
                base.append(part)
        if not base:
            base = ["root"]
        return base

    def _lookup(self, parts: list[str]) -> "FakeDir | FakeFile | FakeSymlink | None":
        node: FakeDir | FakeFile | FakeSymlink = self.root
        for part in parts:
            if part == "root":
                continue
            if not isinstance(node, FakeDir):
                return None
            node = node.entries.get(part)  # type: ignore[assignment]
            if node is None:
                return None
        return node

    def _resolve_symlink(self, node: "FakeDir | FakeFile | FakeSymlink | None",
                          parent_parts: list[str]) -> "FakeDir | FakeFile | None":
        seen = 0
        while isinstance(node, FakeSymlink) and seen < 8:
            parent = self._lookup(parent_parts)
            node = parent.entries.get(node.target) if isinstance(parent, FakeDir) else None
            seen += 1
        return node

    def cwd_display(self) -> str:
        if self.cwd_path == ["root"]:
            return "/"
        return "/" + "/".join(p for p in self.cwd_path if p != "root")

    def chdir(self, path: str) -> str | None:
        target = self._resolve(path)
        node = self._lookup(target)
        if isinstance(node, FakeDir):
            self.cwd_path = target
            return None
        if node is None:
            return f"sh: cd: {path}: No such file or directory"
        return f"sh: cd: {path}: Not a directory"

    def listdir(self, path: str | None = None) -> list[str] | str:
        target = self._resolve(path) if path else self.cwd_path
        node = self._lookup(target)
        if isinstance(node, FakeDir):
            return sorted(node.entries.keys())
        if node is None:
            return f"ls: {path}: No such file or directory"
        return [path or ""]

    def read_file(self, path: str) -> str | None:
        target = self._resolve(path)
        node = self._resolve_symlink(self._lookup(target), target[:-1])
        if isinstance(node, FakeFile):
            return node.content
        return None

    def write_file(self, path: str, content: str) -> None:
        target = self._resolve(path)
        parent = self._lookup(target[:-1])
        if isinstance(parent, FakeDir):
            parent.entries[target[-1]] = FakeFile(content)

    def make_dir(self, path: str) -> None:
        target = self._resolve(path)
        parent = self._lookup(target[:-1])
        if isinstance(parent, FakeDir):
            parent.entries.setdefault(target[-1], FakeDir())

    def remove(self, path: str) -> None:
        target = self._resolve(path)
        parent = self._lookup(target[:-1])
        if isinstance(parent, FakeDir):
            parent.entries.pop(target[-1], None)

    def exists(self, path: str) -> bool:
        return self._lookup(self._resolve(path)) is not None

    def is_dir(self, path: str) -> bool:
        return isinstance(self._lookup(self._resolve(path)), FakeDir)

    def listdir_nodes(self, path: str | None = None) -> "dict[str, FakeDir | FakeFile | FakeSymlink] | str":
        """Like listdir(), but returns {name: node} instead of just names --
        used by `ls -l` to distinguish files from directories per entry."""
        target = self._resolve(path) if path else self.cwd_path
        node = self._lookup(target)
        if isinstance(node, FakeDir):
            return dict(node.entries)
        if node is None:
            return f"ls: {path}: No such file or directory"
        return {(path or ""): node}

    def copy_node(self, src: str, dst: str) -> str | None:
        """cp: deep-copies src onto dst. Returns a busybox-style error
        message on failure, or None on success. Pure in-memory object graph
        copy -- there's no real inode/permission model to preserve."""
        node = self._lookup(self._resolve(src))
        if node is None:
            return f"cp: cannot stat '{src}': No such file or directory"
        dst_parts = self._resolve(dst)
        dst_node = self._lookup(dst_parts)
        if isinstance(dst_node, FakeDir):
            # cp file existing_dir/ -> place inside existing_dir under src's basename
            dst_node.entries[self._resolve(src)[-1]] = deepcopy(node)
            return None
        parent = self._lookup(dst_parts[:-1])
        if not isinstance(parent, FakeDir):
            return f"cp: cannot create '{dst}': No such file or directory"
        parent.entries[dst_parts[-1]] = deepcopy(node)
        return None

    def move_node(self, src: str, dst: str) -> str | None:
        """mv: re-parents the node object (no copy needed) and removes it
        from its original location. Returns a busybox-style error message on
        failure, or None on success."""
        src_parts = self._resolve(src)
        src_parent = self._lookup(src_parts[:-1])
        node = self._lookup(src_parts)
        if node is None or not isinstance(src_parent, FakeDir):
            return f"mv: can't stat '{src}': No such file or directory"
        dst_parts = self._resolve(dst)
        dst_node = self._lookup(dst_parts)
        if isinstance(dst_node, FakeDir):
            dst_node.entries[src_parts[-1]] = node
            del src_parent.entries[src_parts[-1]]
            return None
        parent = self._lookup(dst_parts[:-1])
        if not isinstance(parent, FakeDir):
            return f"mv: can't stat '{dst}': No such file or directory"
        parent.entries[dst_parts[-1]] = node
        del src_parent.entries[src_parts[-1]]
        return None
