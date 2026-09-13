#!/usr/bin/env python3
"""Dynamic version of tools/dashboard.py: serves the same report as a live
Flask page instead of a one-shot static HTML file. Refreshing your browser
(or just leaving the tab open -- it auto-reloads) always reflects the
current var/logs/events.jsonl, instead of needing to re-run the generator
and re-copy the output every time you want an update.

Deliberately still outside honeypot/ package scope, for the same reason as
dashboard.py (see that file's docstring): CLAUDE.md / the build spec mark a
web dashboard as explicitly out of scope for the honeypot itself. This is a
separate, read-only tool you run alongside it -- never imported by, and
never running inside, the honeypot's own process. It reuses dashboard.py's
Report/GeoLookup/render_html rather than duplicating that logic.

Usage:
    python3 tools/dashboard_server.py configs/riscv64.yaml
    python3 tools/dashboard_server.py --events var/logs/events.jsonl --geoip var/GeoLite2-City.mmdb
    python3 tools/dashboard_server.py --events var/logs/events.jsonl --port 8080

Requires the `dashboard-server` extra: pip install -e '.[dashboard-server]'

SECURITY NOTE: every page load shows real captured attacker IPs and
credentials. --host defaults to 127.0.0.1 (loopback only) on purpose --
view it through an SSH tunnel (`ssh -L 5000:localhost:5000 your-host`)
rather than binding a public interface. If you deliberately pass a
non-loopback --host, put a reverse proxy with authentication in front of
this; it has none of its own, and Flask's built-in server is a
development server, not something to expose directly regardless.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from flask import Flask, Response

sys.path.insert(0, str(Path(__file__).parent))
from dashboard import GeoLookup, Report, _load_events, render_html  # noqa: E402

app = Flask(__name__)

# Single-config, single-operator tool (not a multi-tenant app) -- plain
# module globals set once in main() before app.run() are simplest.
_events_path: Path
_geo: GeoLookup
_refresh_seconds: int = 15


@app.route("/")
def index() -> Response:
    events = _load_events(_events_path)
    report = Report(events)
    html_out = render_html(report, _geo)
    if _refresh_seconds > 0:
        html_out = html_out.replace(
            "<head>", f'<head><meta http-equiv="refresh" content="{_refresh_seconds}">', 1,
        )
    return Response(html_out, mimetype="text/html")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", nargs="?", help="honeypot config YAML, used to find the events log by default")
    parser.add_argument("--events", help="explicit path to events.jsonl (overrides --config-derived path)")
    parser.add_argument("--geoip", help="path to a GeoLite2-City.mmdb file (optional)")
    parser.add_argument("--host", default="127.0.0.1",
                         help="address to bind (default: 127.0.0.1 -- loopback only, see SECURITY NOTE above)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--refresh-seconds", type=int, default=15,
                         help="auto-reload the page in the browser this often, 0 disables (default: 15)")
    return parser


def main() -> None:
    global _events_path, _geo, _refresh_seconds

    args = _build_arg_parser().parse_args()

    if args.events:
        _events_path = Path(args.events)
    elif args.config:
        from honeypot.config import load_config
        config = load_config(args.config)
        _events_path = Path(config.logging.log_dir) / config.logging.json_log_filename
    else:
        _build_arg_parser().error("pass either a config YAML or --events path/to/events.jsonl")
        return

    _geo = GeoLookup(Path(args.geoip) if args.geoip else None)
    _refresh_seconds = args.refresh_seconds

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[dashboard_server] WARNING: binding {args.host}, not loopback-only -- "
              f"this page has no authentication and shows real captured credentials. "
              f"Put an authenticating reverse proxy in front of it.", file=sys.stderr)

    print(f"[dashboard_server] serving {_events_path} on http://{args.host}:{args.port}/", file=sys.stderr)
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
