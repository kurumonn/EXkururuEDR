from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

from .collector import collect_linux_summaries, summaries_to_normalized_events
from .config import AgentConfig
from .health import health_snapshot
from .response import append_response_log, execute_response, map_decision_to_response
from .rule_engine import evaluate_events
from .rules import load_local_rules
from .spool import EventSpool
from .xdr_client import (
    export_batch,
    fetch_policy,
    list_actions,
    send_heartbeat,
    send_policy_ack,
    update_action_status,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="exkururuEDR Linux agent skeleton CLI")
    parser.add_argument("--config", required=True, help="agent config JSON path")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="initialize spool/log directories")
    sub.add_parser("health", help="print health snapshot JSON")
    sub.add_parser("heartbeat", help="write heartbeat JSON into log dir")
    sub.add_parser("collect-once", help="collect Linux summaries and print normalized events")
    sub.add_parser("collect-spool", help="collect Linux summaries and enqueue into spool")
    rules_eval = sub.add_parser("rules-eval", help="evaluate event JSON by local YAML rules")
    rules_eval.add_argument("--rules", required=True, help="rules yaml path")
    rules_eval.add_argument("--event-json", required=True, help="event json path")
    collect_eval = sub.add_parser("collect-eval-spool", help="collect -> evaluate -> spool")
    collect_eval.add_argument("--rules", required=True, help="rules yaml path")
    response_exec = sub.add_parser("response-exec", help="execute local response action")
    response_exec.add_argument("--action", required=True, choices=["kill", "quarantine", "isolate"])
    response_exec.add_argument("--target", required=True)
    response_exec.add_argument("--enforce", action="store_true", help="disable dry-run and enforce action")
    collect_resp = sub.add_parser(
        "collect-eval-response",
        help="collect -> evaluate -> execute mapped local responses -> spool",
    )
    collect_resp.add_argument("--rules", required=True, help="rules yaml path")
    collect_resp.add_argument("--enforce", action="store_true", help="disable dry-run and enforce action")
    xdr_export = sub.add_parser("xdr-export-batch", help="export pending spool events to XDR batch API")
    xdr_export.add_argument("--batch-size", type=int, default=100)
    sub.add_parser("xdr-heartbeat", help="send EDR heartbeat event to XDR")
    sub.add_parser("xdr-policy-fetch", help="fetch current policy from XDR")
    xdr_ack = sub.add_parser("xdr-policy-ack", help="send policy apply ACK event to XDR")
    xdr_ack.add_argument("--policy-id", required=True)
    xdr_ack.add_argument("--apply-ok", choices=["true", "false"], default="true")
    xdr_ack.add_argument("--note", default="")
    xdr_dispatch = sub.add_parser("xdr-dispatch-actions", help="pull requested actions from XDR and execute")
    xdr_dispatch.add_argument("--limit", type=int, default=20)
    xdr_dispatch.add_argument("--enforce", action="store_true", help="disable dry-run for local actions")

    enqueue = sub.add_parser("spool-enqueue", help="enqueue single event JSON file")
    enqueue.add_argument("--event-json", required=True)

    sub.add_parser("spool-stats", help="print spool stats JSON")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = AgentConfig.from_file(args.config)
    spool = EventSpool(config.spool_dir, max_spool_files=config.max_spool_files)

    if args.command == "init":
        spool.init_dirs()
        Path(config.log_dir).mkdir(parents=True, exist_ok=True)
        print(json.dumps({"ok": True, "config": config.to_dict()}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "health":
        payload = health_snapshot(config, spool)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    if args.command == "heartbeat":
        spool.init_dirs()
        log_dir = Path(config.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "agent_id": config.agent_id,
            "workspace": config.workspace,
            "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "pending_events": spool.pending_count(),
        }
        out = log_dir / "heartbeat.json"
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"ok": True, "heartbeat_file": str(out), "payload": payload}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "spool-enqueue":
        event = json.loads(Path(args.event_json).read_text(encoding="utf-8"))
        if not isinstance(event, dict):
            raise ValueError("event json must be object")
        spool.enqueue(event)
        print(json.dumps({"ok": True, "spool": spool.stats()}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "spool-stats":
        print(json.dumps(spool.stats(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "collect-once":
        summaries = collect_linux_summaries()
        normalized = summaries_to_normalized_events(summaries, agent_id=config.agent_id)
        print(json.dumps({"ok": True, "events": normalized}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "collect-spool":
        summaries = collect_linux_summaries()
        normalized = summaries_to_normalized_events(summaries, agent_id=config.agent_id)
        for item in normalized:
            spool.enqueue(item)
        print(
            json.dumps(
                {"ok": True, "enqueued": len(normalized), "spool": spool.stats()},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "rules-eval":
        rules = load_local_rules(args.rules)
        event = json.loads(Path(args.event_json).read_text(encoding="utf-8"))
        if not isinstance(event, dict):
            raise ValueError("event json must be object")
        rows = evaluate_events([event], rules)
        print(json.dumps({"ok": True, "evaluated": rows}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "collect-eval-spool":
        rules = load_local_rules(args.rules)
        summaries = collect_linux_summaries()
        normalized = summaries_to_normalized_events(summaries, agent_id=config.agent_id)
        evaluated = evaluate_events(normalized, rules)
        for item in evaluated:
            spool.enqueue(item)
        print(
            json.dumps(
                {
                    "ok": True,
                    "enqueued": len(evaluated),
                    "final_actions": [e.get("local_decision", {}).get("final_action", "allow") for e in evaluated],
                    "spool": spool.stats(),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "response-exec":
        result = execute_response(args.action, args.target, config=config, dry_run=(not args.enforce))
        log_path = append_response_log(config.log_dir, result)
        print(json.dumps({"ok": result.ok, "result": result.to_dict(), "log_file": log_path}, ensure_ascii=False, indent=2))
        return 0 if result.ok else 1

    if args.command == "collect-eval-response":
        rules = load_local_rules(args.rules)
        summaries = collect_linux_summaries()
        normalized = summaries_to_normalized_events(summaries, agent_id=config.agent_id)
        evaluated = evaluate_events(normalized, rules)
        response_results = []
        for event in evaluated:
            mapped = map_decision_to_response(event)
            if mapped is None:
                continue
            action, target = mapped
            result = execute_response(action, target, config=config, dry_run=(not args.enforce))
            append_response_log(config.log_dir, result)
            response_results.append(result.to_dict())
        for item in evaluated:
            spool.enqueue(item)
        print(
            json.dumps(
                {
                    "ok": True,
                    "enqueued": len(evaluated),
                    "responses": response_results,
                    "spool": spool.stats(),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "xdr-export-batch":
        batch = spool.peek_batch(limit=max(1, args.batch_size))
        result = export_batch(config, batch)
        if result["ok"]:
            spool.drop_batch(len(batch))
        print(
            json.dumps(
                {"ok": result["ok"], "result": result, "spool": spool.stats()},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if result["ok"] else 1

    if args.command == "xdr-heartbeat":
        result = send_heartbeat(config, pending_events=spool.pending_count())
        print(json.dumps({"ok": result["ok"], "result": result}, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1

    if args.command == "xdr-policy-fetch":
        result = fetch_policy(config)
        print(json.dumps({"ok": result["ok"], "result": result}, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1

    if args.command == "xdr-policy-ack":
        result = send_policy_ack(
            config,
            policy_id=str(args.policy_id),
            apply_ok=(args.apply_ok == "true"),
            note=str(args.note),
        )
        print(json.dumps({"ok": result["ok"], "result": result}, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1

    if args.command == "xdr-dispatch-actions":
        listed = list_actions(config)
        if not listed["ok"]:
            print(json.dumps({"ok": False, "result": listed}, ensure_ascii=False, indent=2))
            return 1
        requested = [
            item
            for item in listed["items"]
            if isinstance(item, dict) and str(item.get("status", "")).lower() == "requested"
        ][: max(1, args.limit)]
        dispatched = []
        for item in requested:
            action_id = int(item.get("id"))
            action_type = str(item.get("action_type", "")).lower()
            target = str(item.get("target", ""))
            mapped = _map_xdr_action_to_local(action_type, target)
            if mapped is None:
                ack = update_action_status(config, action_id, "failed", f"unsupported_action_type:{action_type}")
                dispatched.append({"action_id": action_id, "ok": False, "reason": "unsupported_action_type", "ack": ack})
                continue
            local_action, local_target = mapped
            result = execute_response(local_action, local_target, config=config, dry_run=(not args.enforce))
            append_response_log(config.log_dir, result)
            ack_status = "completed" if result.ok else "failed"
            ack = update_action_status(config, action_id, ack_status, result.detail)
            dispatched.append(
                {
                    "action_id": action_id,
                    "xdr_action_type": action_type,
                    "local_action": local_action,
                    "target": local_target,
                    "result": result.to_dict(),
                    "ack": ack,
                }
            )
        print(json.dumps({"ok": True, "requested": len(requested), "dispatched": dispatched}, ensure_ascii=False, indent=2))
        return 0

    raise RuntimeError("unknown command")


def _map_xdr_action_to_local(action_type: str, target: str) -> tuple[str, str] | None:
    mapping = {
        "host_isolate": "isolate",
        "edr_isolate": "isolate",
        "process_kill": "kill",
        "file_quarantine": "quarantine",
    }
    local = mapping.get(action_type)
    if local is None:
        return None
    return (local, target)


if __name__ == "__main__":
    raise SystemExit(main())
