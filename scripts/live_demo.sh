#!/usr/bin/env bash
# Live demo: enrichment and shipping run continuously while traffic is replayed
# through the proxy, so detections appear in Kibana as the events arrive.
#
# Usage:  scripts/live_demo.sh [EVENTS] [EVENTS_PER_SECOND]
#         scripts/live_demo.sh 200 2
#
# The capture log is emptied first so the followers do not re-process old events.
# (Documents already in Elasticsearch are left alone.)
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
set -a; source elk/.env; set +a

N="${1:-200}"
RATE="${2:-2}"

: > logs/genai-traffic.jsonl
rm -f logs/genai-enriched.jsonl

python scripts/enrich_stream.py --follow > logs/enrich.log 2>&1 &
ENRICH_PID=$!
python scripts/ship_to_es.py --follow > logs/ship.log 2>&1 &
SHIP_PID=$!
trap 'kill $ENRICH_PID $SHIP_PID 2>/dev/null || true' EXIT

echo "starting enrichment and shipper..."
sleep 10
echo "pipeline live. replaying $N events at $RATE/s. Watch Security > Alerts (last 15 minutes)."
python scripts/replay.py --limit "$N" --rate "$RATE"
echo "replay finished. keeping the pipeline up 90s so the last rule run can fire..."
sleep 90
echo "done."
