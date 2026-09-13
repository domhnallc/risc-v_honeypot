#!/usr/bin/env bash
# Age-based cleanup for the honeypot's var/ directory.
#
# var/logs/events.jsonl is handled separately by logrotate (see
# logrotate-riscv-honeypot.conf in this directory) -- it's one file that
# grows forever via appends, which is exactly what logrotate is for.
#
# This script instead prunes the *other* things that accumulate as many
# small files rather than one growing file, neither of which anything in
# the codebase ever cleans up on its own:
#   - var/transcripts/*.jsonl  -- one file per session, forever
#   - var/jobs/.processing/*   -- claimed job + result files the fetcher
#     leaves behind after processing (honeypot/fetcher/queue.py's
#     claim_pending_jobs moves jobs here; nothing ever deletes them)
#
# var/quarantine/ is deliberately NEVER touched here -- those are captured
# malware samples, not logs, and deleting one should always be a human
# decision, never a cron job's.
#
# Usage:
#   ./cleanup-var.sh                  # apply with the defaults below
#   TRANSCRIPT_RETENTION_DAYS=14 ./cleanup-var.sh
#   DRY_RUN=1 ./cleanup-var.sh         # print what would be deleted, delete nothing
#
# Install as a daily cron job (as root, so it can remove root/UID-10001-
# owned files written by the Docker containers):
#   sudo crontab -e
#   # add:
#   0 3 * * * /root/risc-v_honeypot/deploy/cleanup-var.sh >> /var/log/riscv-honeypot-cleanup.log 2>&1
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VAR_DIR="${VAR_DIR:-$REPO_DIR/var}"
TRANSCRIPT_RETENTION_DAYS="${TRANSCRIPT_RETENTION_DAYS:-30}"
JOB_RETENTION_DAYS="${JOB_RETENTION_DAYS:-7}"
DRY_RUN="${DRY_RUN:-0}"

find_cmd=(find)
if [ "$DRY_RUN" = "1" ]; then
    echo "[cleanup-var] DRY RUN -- listing only, nothing will be deleted"
    action=(-print)
else
    action=(-print -delete)
fi

echo "[cleanup-var] $(date -Is) pruning transcripts older than ${TRANSCRIPT_RETENTION_DAYS}d, job files older than ${JOB_RETENTION_DAYS}d"

if [ -d "$VAR_DIR/transcripts" ]; then
    "${find_cmd[@]}" "$VAR_DIR/transcripts" -maxdepth 1 -name '*.jsonl' \
        -mtime "+${TRANSCRIPT_RETENTION_DAYS}" "${action[@]}"
fi

if [ -d "$VAR_DIR/jobs/.processing" ]; then
    # covers both claimed job files (<job_id>.json) and the fetcher's
    # result files (<job_id>.result.json) -- the latter already ends in
    # .json too, so one pattern catches both.
    "${find_cmd[@]}" "$VAR_DIR/jobs/.processing" -maxdepth 1 -name '*.json' \
        -mtime "+${JOB_RETENTION_DAYS}" "${action[@]}"
fi

echo "[cleanup-var] done"
