"""
shadowai-lab — mitmproxy capture addon
Writes one ECS-aligned JSON record per intercepted HTTP(S) request to a
JSONL log. Observational only: it records what left the host, not whether
that was allowed or whether it contained PII. Those judgements belong to
the enrichment service (PII) and the Sigma detection rules (policy).
"""
import json
from datetime import datetime, timezone
from mitmproxy import http

LOG_PATH = "/logs/genai-traffic.jsonl"
# Cap stored body text so a pathological upload can't blow up the log line.
MAX_BODY_CHARS = 20000


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )[:-3] + "Z"


def request(flow: http.HTTPFlow) -> None:
    r = flow.request

    try:
        body_text = r.get_text(strict=False) or ""
    except Exception:
        body_text = ""
    body_bytes = len(r.raw_content or b"")
    if len(body_text) > MAX_BODY_CHARS:
        body_text = body_text[:MAX_BODY_CHARS]

    src_ip = None
    if flow.client_conn and flow.client_conn.peername:
        src_ip = flow.client_conn.peername[0]

    ts = r.timestamp_start or datetime.now(tz=timezone.utc).timestamp()

    record = {
        "@timestamp": _iso(ts),
        "event": {
            "kind": "event",
            "category": ["web"],
            "type": ["access"],
            "action": "genai-request",
            "dataset": "shadowai.genai",
        },
        "source": {"ip": src_ip},
        "destination": {"domain": r.pretty_host},
        "url": {
            "full": r.pretty_url,
            "domain": r.pretty_host,
            "path": r.path,
        },
        "http": {
            "request": {
                "method": r.method,
                "body": {"bytes": body_bytes, "content": body_text},
            }
        },
        "user_agent": {"original": r.headers.get("user-agent", "")},
    }

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    # Lab replay traffic gets a synthetic reply, so test data never reaches real services.
    if record["user_agent"]["original"].startswith("shadowai-replay/"):
        flow.response = http.Response.make(
            200, b'{"lab":"synthetic"}', {"Content-Type": "application/json"}
        )
