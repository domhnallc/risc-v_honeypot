"""Static-analysis safety net (spec sec 2 / SAFETY.md guarantee 1).

Fails the build if any dangerous call appears anywhere under honeypot/:
os.system, os.exec*, a subprocess call with shell=True, the eval/exec
builtins, or dlopen. This is deliberately a dumb grep-based check (the spec
explicitly calls a "simple grep-based CI check" sufficient) rather than an
AST walk, so it is easy to audit by reading this file alone.

Scoped to honeypot/ (the shipped runtime package), not tests/, so that this
file's own pattern strings don't trip themselves up.
"""
from __future__ import annotations

import re
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "honeypot"

# (pattern, human-readable description)
_FORBIDDEN: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bos\.system\s*\("), "os.system("),
    (re.compile(r"\bos\.exec\w*\s*\("), "os.exec*("),
    (re.compile(r"\bos\.dlopen\s*\("), "os.dlopen("),
    (re.compile(r"\bdlopen\s*\("), "dlopen("),
    (re.compile(r"(?<![\w.])eval\s*\("), "eval( builtin"),
    (re.compile(r"(?<![\w.])exec\s*\("), "exec( builtin"),
    (re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"), "subprocess ... shell=True"),
]


def _all_source_files() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def test_package_root_exists() -> None:
    assert PACKAGE_ROOT.is_dir(), f"expected {PACKAGE_ROOT} to exist"


def test_no_dangerous_calls_in_honeypot_package() -> None:
    violations: list[str] = []
    for path in _all_source_files():
        text = path.read_text(encoding="utf-8")
        for pattern, description in _FORBIDDEN:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                violations.append(f"{path.relative_to(PACKAGE_ROOT.parent)}:{line_no}: {description}")
    assert not violations, "Disallowed call(s) found:\n" + "\n".join(violations)


def test_detector_actually_catches_things() -> None:
    """Guards against the check silently becoming a no-op."""
    sample = "import subprocess\nsubprocess.run(cmd, shell=True)\nos.system('ls')\neval('1')\nexec('1')\n"
    hits = 0
    for pattern, _ in _FORBIDDEN:
        hits += len(pattern.findall(sample))
    assert hits >= 4
