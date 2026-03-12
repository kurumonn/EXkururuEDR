from __future__ import annotations

import argparse
import html
import json
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .config import AgentConfig
from .response import append_response_log, execute_response
from .standalone_storage import EdrStandaloneStorage


def _json_response(handler: BaseHTTPRequestHandler, payload: dict[str, Any], status: int = 200) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _html_response(handler: BaseHTTPRequestHandler, content: str, status: int = 200) -> None:
    raw = content.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        length = 0
    raw = handler.rfile.read(max(0, length))
    if not raw:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("json object required")
    return data


def _render_dashboard(storage: EdrStandaloneStorage) -> str:
    total_events = storage.count_events()
    recent_events = storage.list_events(limit=10)
    alerts = storage.list_alerts(limit=10)
    responses = storage.list_responses(limit=10)
    policy = storage.current_policy()
    rows = []
    for ev in recent_events:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(ev.get('created_at', '')))}</td>"
            f"<td>{html.escape(str(ev.get('event_id', '')))}</td>"
            f"<td>{html.escape(str(ev.get('event_type', '')))}</td>"
            f"<td>{html.escape(str(ev.get('severity', '')))}</td>"
            "</tr>"
        )
    response_rows = []
    for it in responses:
        response_rows.append(
            "<tr>"
            f"<td>{html.escape(str(it.get('created_at', '')))}</td>"
            f"<td>{html.escape(str(it.get('action', '')))}</td>"
            f"<td>{html.escape(str(it.get('target', '')))}</td>"
            f"<td>{html.escape(str(it.get('ok', '')))}</td>"
            f"<td>{html.escape(str(it.get('detail', '')))}</td>"
            "</tr>"
        )
    policy_title = policy.get("title", "none") if policy else "none"
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EXkururuEDR Standalone</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 24px; background: #0b1220; color: #eef4ff; overflow-x: hidden; }}
    .cards {{ display:grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap:12px; }}
    .card {{ background:#141f33; border:1px solid #314970; border-radius:10px; padding:12px; overflow-x: auto; -webkit-overflow-scrolling: touch; }}
    .card h3 {{ margin:0 0 8px; color:#c3d0e8; font-size:13px; }}
    .card p {{ margin:0; font-size:24px; font-weight:700; }}
    table {{ width:100%; border-collapse:collapse; background:#141f33; border:1px solid #314970; margin-top:12px; }}
    th,td {{ padding:8px 10px; border-bottom:1px solid #22314e; text-align:left; font-size:13px; word-break: break-word; overflow-wrap: anywhere; }}
    th {{ color:#c3d0e8; }}
    .section {{ margin-top:20px; }}
    @media (max-width: 900px) {{
      body {{ margin: 14px; }}
      .cards {{ grid-template-columns: repeat(2,minmax(0,1fr)); gap:10px; }}
      .card p {{ font-size: 20px; }}
    }}
    @media (max-width: 600px) {{
      body {{ margin: 10px; }}
      .cards {{ grid-template-columns: 1fr; gap: 8px; }}
      .card {{ padding: 10px; }}
      .card h3 {{ font-size: 12px; }}
      .card p {{ font-size: 18px; }}
      .section {{ margin-top: 14px; }}
      table {{ display: block; overflow-x: auto; white-space: nowrap; }}
      th,td {{ padding: 6px 7px; font-size: 12px; }}
    }}
  </style>
</head>
<body>
  <h1>EXkururuEDR Standalone</h1>
  <div class="cards">
    <div class="card"><h3>Total Events</h3><p>{total_events}</p></div>
    <div class="card"><h3>Alerts</h3><p>{len(alerts)}</p></div>
    <div class="card"><h3>Responses</h3><p>{len(responses)}</p></div>
    <div class="card"><h3>Current Policy</h3><p>{html.escape(policy_title)}</p></div>
  </div>
  <div class="section">
    <h3>Recent Events</h3>
    <table>
      <thead><tr><th>Created</th><th>Event ID</th><th>Type</th><th>Severity</th></tr></thead>
      <tbody>{''.join(rows) or "<tr><td colspan='4'>No events</td></tr>"}</tbody>
    </table>
  </div>
  <div class="section">
    <h3>Recent Responses</h3>
    <table>
      <thead><tr><th>Created</th><th>Action</th><th>Target</th><th>OK</th><th>Detail</th></tr></thead>
      <tbody>{''.join(response_rows) or "<tr><td colspan='5'>No responses</td></tr>"}</tbody>
    </table>
  </div>
</body>
</html>
"""


def create_handler(storage: EdrStandaloneStorage, config: AgentConfig):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            if path == "/healthz":
                return _json_response(self, {"ok": True, "events": storage.count_events()})
            if path == "/dashboard":
                return _html_response(self, _render_dashboard(storage))
            if path == "/api/v1/events":
                limit = int(query.get("limit", ["100"])[0])
                return _json_response(self, {"events": storage.list_events(limit=limit)})
            if path == "/api/v1/alerts":
                limit = int(query.get("limit", ["100"])[0])
                return _json_response(self, {"alerts": storage.list_alerts(limit=limit)})
            if path == "/api/v1/responses":
                limit = int(query.get("limit", ["100"])[0])
                return _json_response(self, {"responses": storage.list_responses(limit=limit)})
            if path == "/api/v1/policy/current":
                return _json_response(self, {"policy": storage.current_policy()})
            return _json_response(self, {"error": "not_found"}, status=404)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                body = _read_json(self)
            except Exception as exc:
                return _json_response(self, {"error": f"bad_json:{exc}"}, status=400)

            if path == "/api/v1/events":
                events_raw = body.get("events")
                if isinstance(events_raw, list):
                    events = [x for x in events_raw if isinstance(x, dict)]
                elif isinstance(body.get("event"), dict):
                    events = [body["event"]]
                else:
                    events = [body] if body else []
                inserted = storage.add_events(events)
                return _json_response(self, {"ok": True, "inserted": inserted})

            if path == "/api/v1/policy":
                title = str(body.get("title", "default-policy"))
                policy = body.get("policy", {})
                if not isinstance(policy, dict):
                    return _json_response(self, {"error": "policy_must_be_object"}, status=400)
                pid = storage.set_policy(title, policy)
                return _json_response(self, {"ok": True, "policy_id": pid})

            if path == "/api/v1/responses/exec":
                action = str(body.get("action", ""))
                target = str(body.get("target", ""))
                dry_run = bool(body.get("dry_run", config.response_dry_run))
                result = execute_response(action=action, target=target, config=config, dry_run=dry_run)
                storage.add_response(result.to_dict())
                append_response_log(config.log_dir, result)
                code = HTTPStatus.OK if result.ok else HTTPStatus.BAD_REQUEST
                return _json_response(self, {"ok": result.ok, "result": asdict(result)}, status=int(code))

            return _json_response(self, {"error": "not_found"}, status=404)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="exkururuEDR standalone API/UI server")
    parser.add_argument("--config", required=True, help="agent config JSON path")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8820)
    parser.add_argument("--db-path", default="/home/kurumonn/exkururuEDR/data/standalone/edr.sqlite3")
    args = parser.parse_args()

    config = AgentConfig.from_file(args.config)
    storage = EdrStandaloneStorage(args.db_path)
    handler = create_handler(storage, config)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"exkururuEDR standalone running on http://{args.host}:{args.port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
