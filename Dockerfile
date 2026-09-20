# Single image shared by both the session-handling service and the fetcher
# worker (see docker-compose.yml) -- they're the same codebase running two
# different entry points, per honeypot/fetcher/fetcher.py's design of taking
# no session/shell state so it can run as a fully separate process.
FROM python:3.11-slim

RUN groupadd --gid 10001 honeypot \
    && useradd --uid 10001 --gid honeypot --create-home --shell /usr/sbin/nologin honeypot

WORKDIR /app

COPY pyproject.toml ./
COPY honeypot ./honeypot
COPY configs ./configs

RUN pip install --no-cache-dir .

RUN mkdir -p var/jobs var/quarantine var/logs var/transcripts var/keys \
    && chown -R honeypot:honeypot /app

USER honeypot

ENTRYPOINT ["python", "-m"]
CMD ["honeypot.main", "configs/riscv64.yaml"]
