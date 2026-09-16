"""Tests for CredentialPolicy's acceptance logic (honeypot/config/schema.py).

accept_any=True accepting a literally-arbitrary credential pair is itself a
honeypot tell (see the pentest note in CLAUDE.md). The realistic
alternative: accept a login when the username is in the small,
persona-appropriate valid_usernames set (default root/admin) and the
password independently appears in a real-world-observed password
wordlist, plus a small always-on allow_list fast path for exact pairs
worth guaranteeing regardless (e.g. Mirai's root/xc3511).

The username side deliberately does NOT gate on a broad wordlist the way
the password side does -- confirmed against real traffic that doing so
lets one source IP succeed with many wildly different usernames against
the same simulated device (one real IP got 9 different accepted
usernames), which is itself a stronger honeypot tell than accept_any: it
looks selective on any single attempt and only falls apart across
repeated attempts from the same source.
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


def test_username_on_the_broad_wordlist_but_not_valid_usernames_is_rejected(tmp_path):
    # The actual finding this covers: a source IP getting many different
    # usernames all accepted against the "same device" is itself a
    # honeypot tell (confirmed against real traffic -- one IP got 9
    # different accepted usernames). "arthur" being a real, commonly-
    # attempted SSH username (on the broad wordlist) must not be enough
    # to succeed on its own -- only valid_usernames gates acceptance.
    policy = _policy(tmp_path, ["root", "arthur"], ["123456"])
    assert policy.is_known_username("arthur") is True  # plausible, for the dashboard's off-wordlist flag
    assert not policy.accepts("arthur", "123456")  # but not an account this device actually has
    assert policy.accepts("root", "123456")


def test_valid_usernames_defaults_to_root_and_admin(tmp_path):
    policy = _policy(tmp_path, ["root", "admin", "guest"], ["123456"])
    assert policy.accepts("root", "123456")
    assert policy.accepts("admin", "123456")
    assert not policy.accepts("guest", "123456")


def test_valid_usernames_is_configurable(tmp_path):
    policy = _policy(tmp_path, ["root", "admin"], ["123456"])
    policy.valid_usernames = ["root"]
    assert policy.accepts("root", "123456")
    assert not policy.accepts("admin", "123456")
