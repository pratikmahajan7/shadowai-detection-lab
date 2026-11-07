"""Measure time-to-detection from the alerts Kibana produced (RQ3).

For every alert, latency is measured from the moment the proxy captured the request
(alert's original event time) to the moment Kibana created the alert, and is split
into pipeline stages using the timestamps each stage stamped on the event:

  capture -> enriched   (PII recognition)
  enriched -> shipped   (shipper batching)
  shipped -> alert      (waiting for the next scheduled rule run + rule execution)
  capture -> alert      (total, i.e. detection latency)

Only alerts whose source event was captured in the chosen window are used, so
retrospective alerts from earlier backfills do not distort the numbers.

Usage:
  set -a; source elk/.env; set +a
  python scripts/measure_mttd.py --since now-20m
"""
import argparse
import json
import os
import statistics
import sys
from datetime import datetime
from pathlib import Path

from elasticsearch import Elasticsearch, helpers

def get(src, dotted):
    """Read a dotted field from a stored alert: flat key first, then nested objects."""
    if dotted in src:
        return src[dotted]
    cur = src
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def ts(v):
    if isinstance(v, list):
        v = v[0] if v else None
    return datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None


def pct(sorted_vals, p):
    if not sorted_vals:
        return None
    k = min(len(sorted_vals) - 1, int(round(p / 100 * (len(sorted_vals) - 1))))
    return sorted_vals[k]


def summarise(vals):
    v = sorted(vals)
    if not v:
        return {"n": 0}
    return {"n": len(v), "median_s": round(statistics.median(v), 2),
            "p95_s": round(pct(v, 95), 2), "max_s": round(v[-1], 2), "min_s": round(v[0], 2)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="now-20m", help="only alerts whose event was captured since then")
    ap.add_argument("--es", default="http://localhost:9200")
    ap.add_argument("--out", default="results/mttd.json")
    args = ap.parse_args()

    pw = os.environ.get("ELASTIC_PASSWORD")
    if not pw:
        sys.exit("ELASTIC_PASSWORD not set. Run: set -a; source elk/.env; set +a")
    es = Elasticsearch(args.es, basic_auth=("elastic", pw))

    q = {"range": {"kibana.alert.original_time": {"gte": args.since}}}
    legs = {"capture_to_enriched": [], "enriched_to_shipped": [], "shipped_to_alert": [], "capture_to_alert": []}
    per_rule = {}
    n = 0
    for hit in helpers.scan(es, index=".alerts-security.alerts-default", query={"query": q},
                            _source=["@timestamp", "kibana.alert.original_time", "kibana.alert.rule.name", "shadowai*"]):
        f = hit["_source"]
        cap, alert = ts(get(f, "kibana.alert.original_time")), ts(get(f, "@timestamp"))
        enr, shp = ts(get(f, "shadowai.enriched_at")), ts(get(f, "shadowai.shipped_at"))
        if not (cap and alert and enr and shp):
            continue
        n += 1
        total = (alert - cap).total_seconds()
        legs["capture_to_enriched"].append((enr - cap).total_seconds())
        legs["enriched_to_shipped"].append((shp - enr).total_seconds())
        legs["shipped_to_alert"].append((alert - shp).total_seconds())
        legs["capture_to_alert"].append(total)
        rule = str(get(f, "kibana.alert.rule.name") or "?").split(":")[0]
        per_rule.setdefault(rule, []).append(total)

    if n == 0:
        sys.exit("no alerts with complete timestamps in that window; run live_demo.sh first or widen --since")
    out = {"window": args.since, "alerts": n,
           "stages": {k: summarise(v) for k, v in legs.items()},
           "by_rule_total": {k: summarise(v) for k, v in sorted(per_rule.items())}}
    for k, v in out["stages"].items():
        print(f"{k:22} {v}")
    print("by rule (capture -> alert):")
    for k, v in out["by_rule_total"].items():
        print(f"  {k:12} {v}")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2))
    print("wrote", args.out)


if __name__ == "__main__":
    main()
