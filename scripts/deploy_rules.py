"""Deploy the Sigma rules to Kibana as custom-query detection rules.

The Sigma YAML stays the source of truth: each rule's Sigma UUID becomes the Kibana
rule_id, the Lucene query is the pySigma output (scripts/convert_rules.py), and
severity comes from the Sigma level. Re-running updates rules in place.

Usage (password from the environment):
  set -a; source elk/.env; set +a
  python scripts/deploy_rules.py --dry-run     # print what would be sent
  python scripts/deploy_rules.py               # create or update the rules
"""
import argparse
import glob
import json
import os
import sys
from pathlib import Path

import requests
import yaml

RISK = {"low": 21, "medium": 47, "high": 73, "critical": 99}


def build_payloads(args) -> list:
    queries = json.loads(Path("rules/converted_queries.json").read_text())
    out = []
    for p in sorted(glob.glob("rules/shadowai_r*.yml")):
        meta = yaml.safe_load(Path(p).read_text())
        level = str(meta.get("level", "medium"))
        out.append({
            "rule_id": meta["id"],
            "name": f"{meta['name']}: {meta['title']}",
            "description": meta.get("description", meta["title"]),
            "risk_score": RISK[level],
            "severity": level,
            "type": "query",
            "language": "lucene",
            "query": queries[meta["name"]]["query"],
            "index": [args.index],
            "interval": args.interval,
            "from": args.lookback,
            "max_signals": 1000,
            "enabled": True,
            "tags": ["shadowai", "sigma"],
        })
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kibana", default="http://localhost:5601")
    ap.add_argument("--index", default="shadowai-genai")
    ap.add_argument("--interval", default="1m")
    ap.add_argument("--lookback", default="now-24h", help="how far back each run looks")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    payloads = build_payloads(args)
    if args.dry_run:
        for pl in payloads:
            print(json.dumps(pl, indent=2))
        return

    pw = os.environ.get("ELASTIC_PASSWORD")
    if not pw:
        sys.exit("ELASTIC_PASSWORD not set. Run: set -a; source elk/.env; set +a")
    s = requests.Session()
    s.auth = ("elastic", pw)
    s.headers.update({"kbn-xsrf": "true", "Content-Type": "application/json"})
    url = args.kibana + "/api/detection_engine/rules"

    # make sure the detection alerts index exists (harmless if it already does)
    r = s.post(args.kibana + "/api/detection_engine/index")
    print("alerts index:", r.status_code)

    for pl in payloads:
        r = s.post(url, json=pl)
        action = "created"
        if r.status_code == 409:
            r = s.put(url, json=pl)
            action = "updated"
        if r.ok:
            print(f"{pl['name'][:60]:60} {action}")
        else:
            print(f"{pl['name'][:60]:60} FAILED {r.status_code} {r.text[:300]}", file=sys.stderr)


if __name__ == "__main__":
    main()
