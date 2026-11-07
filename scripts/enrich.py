"""Add PII fields to events using the layered recogniser (the 'enrichment' pipeline stage)."""
import json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pii_recogniser import Recogniser
STRONG = {"EMAIL", "PHONE_NUM", "ID_NUM", "URL", "ADDRESS"}
def main(src, dst):
    rec = Recogniser(use_spacy=True); t0 = time.time(); n = 0
    with open(src) as f, open(dst, "w") as o:
        for line in f:
            e = json.loads(line); sp = rec.spans(e["http.request.body.content"])
            types = sorted({s.type for s in sp})
            e["pii.count"] = len(sp); e["pii.types"] = types; e["pii.types_distinct"] = len(types)
            e["pii.strong_count"] = sum(s.type in STRONG for s in sp)
            o.write(json.dumps(e) + "\n"); n += 1
    print(f"enriched {n} events in {time.time()-t0:.0f}s ({(time.time()-t0)/n*1000:.0f} ms/event)")
main(sys.argv[1], sys.argv[2])
