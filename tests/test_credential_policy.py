"""Tests for CredentialPolicy's wordlist-based acceptance (honeypot/config/schema.py).

accept_any=True accepting a literally-arbitrary credential pair is itself a
honeypot tell (see the pentest note in CLAUDE.md); this is the realistic
alternative: accept only when username and password each independently
appear in a real-world-observed wordlist, plus a small always-on allow_list
fast path for exact pairs worth guaranteeing regardless of the wordlists
(e.g. Mirai's root/xc3511).
"""
from __future__ import annotations

from honeypot.config.schema import Credential, CredentialPolicy


def _policy(tmp_path, usernames, passwords, allow_list=None) -> CredentialPolicy:
    user_file = tmp_path / "users.txt"
    pass_file = tmp_path / "passwords.txt"
    user_file.write_text("\n".join(usernames) + "\n")
    pass_file.write_text("\n".join(passwords) + "\n")
    return CredentialPolicy(
        accept_any=False,
        allow_list=[Credential(**c) for c in (allow_list or [])],
        username_wordlist_path=user_file,
        password_wordlist_path=pass_file,
    )


def test_accepts_when_both_sides_are_on_their_wordlist(tmp_path):
    policy = _policy(tmp_path, ["root", "admin"], ["123456", "password"])
    assert policy.accepts("root", "123456")
    assert policy.accepts("admin", "password")


def test_rejects_when_either_side_is_off_wordlist(tmp_path):
    policy = _policy(tmp_path, ["root", "admin"], ["123456", "password"])
    assert not policy.accepts("root", "not-a-real-password-zzz")
    assert not policy.accepts("some_probe_user", "123456")
    assert not policy.accepts("some_probe_user", "not-a-real-password-zzz")


def test_allow_list_is_an_always_accepted_fast_path_even_if_off_wordlist(tmp_path):
    policy = _policy(
        tmp_path, ["root"], ["123456"],
        allow_list=[{"username": "root", "password": "xc3511"}],
    )
    assert policy.accepts("root", "xc3511")  # not on the password wordlist, but in allow_list


def test_is_known_returns_none_when_no_wordlist_configured():
    policy = CredentialPolicy(accept_any=False)
    assert policy.is_known_username("root") is None
    assert policy.is_known_password("toor") is None


def test_is_known_returns_bool_when_wordlist_configured(tmp_path):
    policy = _policy(tmp_path, ["root"], ["123456"])
    assert policy.is_known_username("root") is True
    assert policy.is_known_username("nobody") is False
    assert policy.is_known_password("123456") is True
    assert policy.is_known_password("nope") is False


def test_accept_any_still_bypasses_everything(tmp_path):
    policy = _policy(tmp_path, ["root"], ["123456"])
    policy.accept_any = True
    assert policy.accepts("literally-anything", "literally-anything")
