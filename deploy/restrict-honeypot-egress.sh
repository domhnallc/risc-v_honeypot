#!/usr/bin/env bash
# Blocks the `honeypot` container's own outbound-*initiated* connections at
# the host firewall -- defense-in-depth against a hypothetical future
# code-level compromise of that container (not attacker-supplied payload
# execution, which the codebase already prevents by design -- see
# SAFETY.md guarantee #1 -- but a bug in our own Python, or in asyncssh/
# aiohttp themselves, that gave an attacker real code execution inside it).
#
# Safe with zero functional impact: the honeypot container has no
# legitimate outbound need at all once fetcher.mode: queued is set (see
# README "Firewall and ports") -- it only ever accepts inbound attacker
# connections and replies to them, and writes job files to a local shared
# bind mount. It never dials out on its own. This rule blocks *new*
# outbound connections from that container's subnet while leaving inbound
# attacker traffic and replies to it untouched -- a reply within an
# already-established inbound connection has conntrack state ESTABLISHED,
# not NEW, so it's unaffected.
#
# Uses Docker's DOCKER-USER chain specifically because Docker never
# touches or overwrites rules there -- they survive `docker compose
# restart`/`up` and Docker daemon restarts, unlike rules added to Docker's
# own generated chains. DOCKER-USER itself is recreated empty on every
# Docker daemon start though, so this script needs to re-run after every
# boot -- see restrict-honeypot-egress.service in this directory, a
# systemd unit that does exactly that.
set -euo pipefail

NETWORK_NAME="${NETWORK_NAME:-risc-v_honeypot_public}"

subnet=""
for _ in $(seq 1 30); do
    subnet=$(docker network inspect "$NETWORK_NAME" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null) && break
    sleep 1
done

if [ -z "$subnet" ]; then
    echo "[restrict-egress] timed out waiting for docker network '$NETWORK_NAME' to exist -- is 'docker compose up -d' running?" >&2
    exit 1
fi

if iptables -C DOCKER-USER -s "$subnet" -m conntrack --ctstate NEW -j DROP 2>/dev/null; then
    echo "[restrict-egress] $(date -Is) rule already present for $subnet -- nothing to do"
else
    iptables -I DOCKER-USER -s "$subnet" -m conntrack --ctstate NEW -j DROP
    echo "[restrict-egress] $(date -Is) blocked new outbound connections from $subnet ($NETWORK_NAME)"
fi
