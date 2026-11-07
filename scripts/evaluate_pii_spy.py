"""Evaluate the recogniser on SPY. Span-level (exact + overlap) per entity type,
and document-level 'contains any PII' detection."""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pii_recogniser import Recogniser  # noqa: E402
from spy_loader import ENT_TYPES, load_corpus  # noqa: E402


def overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="tune", choices=["tune", "heldout"])
    ap.add_argument("--corpus", default="data/spy_filled.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-spacy", action="store_true")
    ap.add_argument("--out", default="")
    ap.add_argument("--show-misses", type=int, default=0)
    args = ap.parse_args()

    docs = [d for d in load_corpus(Path(args.corpus)) if d["pool"] == args.pool]
    if args.limit:
        docs = docs[: args.limit]
    rec = Recogniser(use_spacy=not args.no_spacy)

    c = {t: defaultdict(int) for t in ENT_TYPES}
    misses = defaultdict(list)
    fps = defaultdict(list)
    doc_hit = 0
    for d in docs:
        pred = rec.spans(d["text"])
        gold = d["entities"]
        if pred:
            doc_hit += 1
        for t in ENT_TYPES:
            g = [(e["start"], e["end"]) for e in gold if e["type"] == t]
            p = [(s.start, s.end) for s in pred if s.type == t]
            gset, pset = set(g), set(p)
            c[t]["gold"] += len(g)
            c[t]["pred"] += len(p)
            c[t]["tp_exact"] += len(gset & pset)
            c[t]["tp_overlap"] += sum(any(overlap(x, y) for y in p) for x in g)
            c[t]["pred_overlap_ok"] += sum(any(overlap(x, y) for y in g) for x in p)
            for x in g:
                if not any(overlap(x, y) for y in p) and len(misses[t]) < args.show_misses:
                    misses[t].append(d["text"][x[0]:x[1]])
            for y in p:
                if not any(overlap(x, y) for x in g) and len(fps[t]) < args.show_misses:
                    fps[t].append(d["text"][y[0]:y[1]])

    res = {"pool": args.pool, "n_docs": len(docs), "types": {}}
    print(f"pool={args.pool} docs={len(docs)}")
    print(f"{'type':10} {'gold':>6} {'pred':>6} {'P(ovl)':>7} {'R(ovl)':>7} {'F1(ovl)':>8} {'R(exact)':>9}")
    tg = tp = tpo = tpp = 0
    for t in ENT_TYPES:
        x = c[t]
        P = x["pred_overlap_ok"] / x["pred"] if x["pred"] else 0.0
        R = x["tp_overlap"] / x["gold"] if x["gold"] else 0.0
        F = 2 * P * R / (P + R) if P + R else 0.0
        Re = x["tp_exact"] / x["gold"] if x["gold"] else 0.0
        res["types"][t] = dict(gold=x["gold"], pred=x["pred"], precision=P, recall=R, f1=F, recall_exact=Re)
        print(f"{t:10} {x['gold']:6d} {x['pred']:6d} {P:7.3f} {R:7.3f} {F:8.3f} {Re:9.3f}")
        tg += x["gold"]; tp += x["pred"]; tpo += x["tp_overlap"]; tpp += x["pred_overlap_ok"]
    P = tpp / tp if tp else 0; R = tpo / tg if tg else 0
    res["micro"] = dict(precision=P, recall=R, f1=2 * P * R / (P + R) if P + R else 0)
    print(f"{'MICRO':10} {tg:6d} {tp:6d} {P:7.3f} {R:7.3f} {res['micro']['f1']:8.3f}")
    docs_with_gold = sum(1 for d in docs if d["entities"])
    res["doc_level"] = dict(docs_with_gold=docs_with_gold, docs_flagged=doc_hit)
    print(f"docs with gold PII={docs_with_gold}, docs flagged={doc_hit}")
    for t in ENT_TYPES:
        if misses[t]:
            print("MISS", t, misses[t])
        if fps[t]:
            print("FP  ", t, fps[t])
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
