"""Ship enriched events to Elasticsearch.

Creates (or updates) the index template first, because the Sigma rules depend on
exact field types: keyword fields for domain/category/path matching and integer
fields for the pii.* counts. A wrong dynamic mapping would make a rule silently
never match.

Document ids are a hash of the input line, so re-running the shipper over the same
file overwrites rather than duplicates (safe to restart during a demo).

shadowai.shipped_at is stamped here; with the capture @timestamp and
shadowai.enriched_at it gives the pipeline legs of the MTTD measurement.

Usage (password comes from the environment, never the command line):
  source elk/.env
  python scripts/ship_to_es.py              # ship what exists, exit
  python scripts/ship_to_es.py --follow     # keep tailing
"""
import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from elasticsearch import Elasticsearch, helpers

INDEX = "shadowai-genai"
KW = {"type": "keyword", "ignore_above": 2048}
MAPPINGS = {
    "dynamic": True,
    "properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {"kind": KW, "category": KW, "type": KW, "action": KW, "dataset": KW}},
        "source": {"properties": {"ip": {"type": "ip"}}},
        "destination": {"properties": {"domain": KW}},
        "url": {"properties": {"full": KW, "domain": KW, "path": KW}},
        "http": {"properties": {"request": {"properties": {
            "method": KW,
            "body": {"properties": {"bytes": {"type": "long"}, "content": {"type": "text"}}},
        }}}},
        "user_agent": {"properties": {"original": KW}},
        "domain_category": KW,
        "pii": {"properties": {
            "count": {"type": "integer"},
            "types": KW,
            "types_distinct": {"type": "integer"},
            "strong_count": {"type": "integer"},
        }},
        "shadowai": {"properties": {
            "event_id": KW,
            "enriched_at": {"type": "date"},
            "shipped_at": {"type": "date"},
        }},
    },
}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def read_lines(path: Path, follow: bool):
    """Yield complete lines; in follow mode also yield None whenever the file is idle."""
    while not path.exists():
        if not follow:
            sys.exit(f"input not found: {path}")
        time.sleep(1)
    with open(path, encoding="utf-8") as f:
        while True:
            pos = f.tell()
            line = f.readline()
            if line.endswith("\n"):
                yield line
                continue
            if not follow:
                if line:
                    yield line
                return
            f.seek(pos)
            yield None
            time.sleep(0.3)


def to_actions(batch):
    for line in batch:
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            print("skipping malformed line", file=sys.stderr)
            continue
        doc.setdefault("shadowai", {})["shipped_at"] = now()
        yield {"_index": INDEX, "_id": hashlib.sha1(line.encode()).hexdigest(), "_source": doc}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="logs/genai-enriched.jsonl")
    ap.add_argument("--es", default="http://localhost:9200")
    ap.add_argument("--follow", action="store_true")
    args = ap.parse_args()

    pw = os.environ.get("ELASTIC_PASSWORD")
    if not pw:
        sys.exit("ELASTIC_PASSWORD not set. Run: source elk/.env")
    es = Elasticsearch(args.es, basic_auth=("elastic", pw))
    es.indices.put_index_template(
        name=INDEX, index_patterns=[INDEX + "*"], priority=200, template={"mappings": MAPPINGS})
    print("index template applied")

    sent = 0
    batch = []

    def flush():
        nonlocal sent, batch
        if not batch:
            return
        ok, errs = helpers.bulk(es, to_actions(batch), raise_on_error=False, refresh=True)
        sent += ok
        if errs:
            print("bulk errors:", errs[:2], file=sys.stderr)
        print(f"shipped {sent}", flush=True)
        batch = []

    for line in read_lines(Path(args.src), args.follow):
        if line is not None:
            batch.append(line)
        if batch and (line is None or len(batch) >= 200):
            flush()
    flush()
    print(f"done, shipped {sent}")


if __name__ == "__main__":
    main()
