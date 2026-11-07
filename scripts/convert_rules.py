"""Convert the Sigma rules to Elasticsearch Lucene queries with pySigma.

The Sigma YAML stays the single source of truth (vendor-neutral); the Lucene
queries are generated output, written to rules/converted_queries.json.
"""
import glob
import json
import sys
from pathlib import Path

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection

out = {}
for p in sorted(glob.glob("rules/shadowai_r*.yml")):
    coll = SigmaCollection.from_yaml(Path(p).read_text())
    rule = coll.rules[0]
    queries = LuceneBackend().convert(coll)
    out[rule.name or Path(p).stem] = {"title": rule.title, "level": str(rule.level), "query": queries[0]}
    print(f"{rule.name}: {queries[0]}")
Path("rules/converted_queries.json").write_text(json.dumps(out, indent=2))
print(f"wrote {len(out)} queries to rules/converted_queries.json", file=sys.stderr)
