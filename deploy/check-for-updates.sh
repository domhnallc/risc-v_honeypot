#!/usr/bin/env bash
# Reminder-only, never automatic: security patches in the base image
# (Dockerfile: FROM python:3.11-slim, a floating tag) and in dependencies
# pinned loosely with >= in pyproject.toml (asyncssh, aiohttp, pydantic,
# PyYAML) only actually reach the running containers when you rebuild.
# An image built once and left running indefinitely silently accumulates
# unpatched CVEs in both. This script only tells you when a rebuild is
# worth doing -- it never pulls, builds, or restarts anything itself,
# since auto-deploying unreviewed upstream changes to an internet-facing
# service has its own risk.
#
# Install as a weekly cron job (as root):
#   sudo crontab -e
#   # add:
#   0 4 * * 1 /root/risc-v_honeypot/deploy/check-for-updates.sh >> /var/log/riscv-honeypot-updates.log 2>&1
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "[check-for-updates] $(date -Is)"

git fetch --quiet origin main 2>/dev/null || echo "[check-for-updates] warning: git fetch failed (offline?)"
behind=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
if [ "$behind" -gt 0 ]; then
    echo "[check-for-updates] $behind new commit(s) on origin/main not yet deployed here -- consider: git pull && docker compose build && docker compose up -d"
fi

created=$(docker image inspect risc-v_honeypot-honeypot --format '{{.Created}}' 2>/dev/null || true)
if [ -n "$created" ]; then
    created_epoch=$(date -d "$created" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    age_days=$(( (now_epoch - created_epoch) / 86400 ))
    if [ "$age_days" -ge 30 ]; then
        echo "[check-for-updates] honeypot image is ${age_days}d old -- rebuild periodically to pick up base-image (python:3.11-slim) and dependency security patches: docker compose build --pull && docker compose up -d"
    fi
fi

if [ "$behind" -eq 0 ] && [ "${age_days:-0}" -lt 30 ]; then
    echo "[check-for-updates] up to date -- no action needed"
fi
