"""Shared fixtures."""
import pytest

from honeypot.fetcher import stage2


@pytest.fixture(autouse=True)
def _fresh_stage2_limiter(monkeypatch):
    """Stage-two budgets live in a process-wide limiter; without a fresh one
    per test, URLs fetched by one test would be 'already seen' in the next."""
    monkeypatch.setattr(stage2, "DEFAULT_LIMITER", stage2.Stage2Limiter())
