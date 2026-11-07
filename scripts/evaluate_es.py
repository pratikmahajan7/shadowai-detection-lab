"""Score the detection rules as they run inside Elasticsearch.

Each Sigma rule (converted to Lucene by convert_rules.py) is run against the
index; alerted events are joined to ground truth by shadowai.event_id, giving a
confusion matrix per rule. Only events that were replayed (have a truth label)
are scored, so stray test records are ignored.

Usage:
  set -a; source elk/.env; set +a
  python scripts/evaluate_es.py --truth data/traffic/events_dev.jsonl
"""
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from elasticsearch import Elasticsearch, helpers

INDEX = "shadowai-genai"


def confusion(alerted: set, universe: dict) -> dict:
    tp = sum(1 for i in alerted if universe[i]["label"] == 1)
    fp = len(alerted) - tp
    pos = sum(1 for v in universe.values() if v["label"] == 1)
    fn = pos - tp
    tn = len(universe) - tp - fp - fn
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": p, "recall": r,
            "f1": 2 * p * r / (p + r) if p + r else 0.0,
            "fp_per_1000_benign": 1000 * fp / (fp + tn) if fp + tn else 0.0}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", default="data/traffic/events_dev.jsonl")
    ap.add_argument("--queries", default="rules/converted_queries.json")
    ap.add_argument("--es", default="http://localhost:9200")
    ap.add_argument("--out", default="results/es_confusion.json")
    args = ap.parse_args()

    pw = os.environ.get("ELASTIC_PASSWORD")
    if not pw:
        sys.exit("ELASTIC_PASSWORD not set. Run: set -a; source elk/.env; set +a")
    es = Elasticsearch(args.es, basic_auth=("elastic", pw))

    truth = {}
    with open(args.truth, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            truth[e["event_id"]] = {"label": e["label"], "scenario": e["scenario"]}

    def ids(query):
        out = set()
        for hit in helpers.scan(es, index=INDEX, query={"query": query}, _source=["shadowai.event_id"]):
            eid = (hit["_source"].get("shadowai") or {}).get("event_id")
            if eid in truth:
                out.add(eid)
        return out

    universe_ids = ids({"match_all": {}})
    universe = {i: truth[i] for i in universe_ids}
    print(f"scoring {len(universe)} replayed events "
          f"({sum(v['label'] for v in universe.values())} positives)")

    rules = json.loads(Path(args.queries).read_text())
    results, alerts = {}, {}
    for name, r in rules.items():
        alerts[name] = ids({"query_string": {"query": r["query"], "analyze_wildcard": True}})
        results[name] = confusion(alerts[name], universe)
    results["any-rule (union)"] = confusion(set().union(*alerts.values()), universe)

    for name, c in results.items():
        print(f"{name:18} TP={c['TP']:4d} FP={c['FP']:4d} FN={c['FN']:4d} TN={c['TN']:4d}  "
              f"P={c['precision']:.3f} R={c['recall']:.3f} F1={c['f1']:.3f} FP/1k={c['fp_per_1000_benign']:.1f}")

    by_scen = {}
    for name, a in alerts.items():
        for i in a:
            by_scen.setdefault(universe[i]["scenario"], Counter())[name] += 1
    sizes = Counter(v["scenario"] for v in universe.values())
    print("\nalerts by scenario (n events):")
    for s in sorted(sizes):
        print(f"  {s} ({sizes[s]}):", dict(by_scen.get(s, {})))

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(results, indent=2))
    print("wrote", args.out)


if __name__ == "__main__":
    main()
