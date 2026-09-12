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
#
# subprocess(...)/Popen(...) calls are handled separately below rather than
# with a single regex here: a naive `subprocess\.\w+\([^)]*shell\s*=\s*True`
# pattern stops at the first literal ')', so it silently misses any call
# with a nested-parenthesized argument before shell=True (e.g.
# `subprocess.run(build_cmd(), shell=True)`). _find_dangerous_subprocess_calls
# walks matching parens instead so it can't be evaded that way.
_FORBIDDEN: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bos\.system\s*\("), "os.system("),
    (re.compile(r"\bos\.exec\w*\s*\("), "os.exec*("),
    (re.compile(r"\bos\.popen\s*\("), "os.popen("),
    (re.compile(r"\bos\.dlopen\s*\("), "os.dlopen("),
    (re.compile(r"(?<![\w.])dlopen\s*\("), "dlopen("),
    (re.compile(r"\bctypes\.CDLL\s*\("), "ctypes.CDLL("),
    (re.compile(r"\bctypes\.PyDLL\s*\("), "ctypes.PyDLL("),
    (re.compile(r"\bctypes\.cdll\.LoadLibrary\s*\("), "ctypes.cdll.LoadLibrary("),
    (re.compile(r"(?<![\w.])eval\s*\("), "eval( builtin"),
    (re.compile(r"(?<![\w.])exec\s*\("), "exec( builtin"),
]

_SUBPROCESS_CALL_START = re.compile(r"\bsubprocess\.\w+\s*\(")
_SHELL_TRUE = re.compile(r"shell\s*=\s*True")


def _all_source_files() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def _extract_balanced_call(text: str, open_paren_idx: int) -> str:
    """Return text from `open_paren_idx` (a '(') through its matching ')',
    tracking paren depth so nested calls don't end the extraction early."""
    depth = 0
    for i in range(open_paren_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_idx:i + 1]
    return text[open_paren_idx:]


def _find_dangerous_subprocess_calls(text: str) -> list[int]:
    """Return the start offset of every subprocess.*(...) call whose full,
    paren-balanced argument list contains shell=True anywhere in it."""
    offsets = []
    for call_match in _SUBPROCESS_CALL_START.finditer(text):
        open_paren_idx = call_match.end() - 1
        call_text = _extract_balanced_call(text, open_paren_idx)
        if _SHELL_TRUE.search(call_text):
            offsets.append(call_match.start())
    return offsets


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
        for offset in _find_dangerous_subprocess_calls(text):
            line_no = text.count("\n", 0, offset) + 1
            violations.append(f"{path.relative_to(PACKAGE_ROOT.parent)}:{line_no}: subprocess ... shell=True")
    assert not violations, "Disallowed call(s) found:\n" + "\n".join(violations)


def test_detector_actually_catches_things() -> None:
    """Guards against the check silently becoming a no-op."""
    sample = "import subprocess\nsubprocess.run(cmd, shell=True)\nos.system('ls')\neval('1')\nexec('1')\n"
    hits = 0
    for pattern, _ in _FORBIDDEN:
        hits += len(pattern.findall(sample))
    hits += len(_find_dangerous_subprocess_calls(sample))
    assert hits >= 4


def test_subprocess_detector_survives_nested_parens() -> None:
    """Regression test for the evasion this check used to have: shell=True
    reached through a nested-parenthesized argument must still be caught."""
    sample = "subprocess.run(build_cmd(), shell=True)\n"
    assert _find_dangerous_subprocess_calls(sample)


def test_detector_flags_popen_and_ctypes_loading() -> None:
    sample = "os.popen(x)\nctypes.CDLL(x)\nctypes.PyDLL(x)\nctypes.cdll.LoadLibrary(x)\n"
    hits = sum(len(pattern.findall(sample)) for pattern, _ in _FORBIDDEN)
    assert hits >= 4
