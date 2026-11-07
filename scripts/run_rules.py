"""Minimal Sigma evaluator (selections, |contains/|gte/|endswith, lists, and/or/not) + confusion matrix.
Rules stay as standard Sigma YAML so pySigma can convert them to Elastic queries later."""
import argparse, json, re, sys
from pathlib import Path
import yaml

def match_sel(sel, ev):
    for key, want in sel.items():
        field, _, mod = key.partition("|"); val = ev.get(field)
        wants = want if isinstance(want, list) else [want]
        def one(w):
            if val is None: return False
            if mod == "contains": return str(w) in str(val)
            if mod == "endswith": return str(val).endswith(str(w))
            if mod == "gte": return float(val) >= float(w)
            return str(val) == str(w)
        if not any(one(w) for w in wants): return False
    return True

def eval_cond(cond, sels, ev):
    toks = re.findall(r"\(|\)|[\w]+", cond); pos = [0]
    def peek(): return toks[pos[0]] if pos[0] < len(toks) else None
    def nxt(): pos[0] += 1; return toks[pos[0]-1]
    def p_or():
        v = p_and()
        while peek() == "or": nxt(); v = p_and() or v
        return v
    def p_and():
        v = p_not()
        while peek() == "and": nxt(); r = p_not(); v = v and r
        return v
    def p_not():
        if peek() == "not": nxt(); return not p_not()
        return p_atom()
    def p_atom():
        t = nxt()
        if t == "(": v = p_or(); nxt(); return v
        return match_sel(sels[t], ev)
    return p_or()

def load_rules(d):
    out = []
    for p in sorted(Path(d).glob("*.yml")):
        r = yaml.safe_load(p.read_text()); det = r["detection"]
        out.append((r["id"], r["title"], det["condition"], {k: v for k, v in det.items() if k != "condition"}))
    return out

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("events"); ap.add_argument("--rules", default="rules")
    ap.add_argument("--out", default=""); a = ap.parse_args()
    evs = [json.loads(l) for l in open(a.events)]; rules = load_rules(a.rules)
    res = {}
    def report(name, pred):
        tp = sum(p and e["label"] for p, e in zip(pred, evs)); fp = sum(p and not e["label"] for p, e in zip(pred, evs))
        fn = sum((not p) and e["label"] for p, e in zip(pred, evs)); tn = len(evs) - tp - fp - fn
        P = tp/(tp+fp) if tp+fp else 0; R = tp/(tp+fn) if tp+fn else 0
        res[name] = dict(TP=tp, FP=fp, FN=fn, TN=tn, precision=P, recall=R, f1=2*P*R/(P+R) if P+R else 0,
                         fpr=fp/(fp+tn) if fp+tn else 0, fp_per_1000_benign=1000*fp/(fp+tn) if fp+tn else 0)
        r = res[name]; print(f"{name:34} TP={tp:4d} FP={fp:4d} FN={fn:4d} TN={tn:4d}  P={P:.3f} R={R:.3f} F1={r['f1']:.3f} FP/1k={r['fp_per_1000_benign']:.1f}")
    allp = []
    for rid, title, cond, sels in rules:
        pred = [eval_cond(cond, sels, e) for e in evs]; allp.append(pred); report(rid, pred)
    report("any-rule (union)", [any(x) for x in zip(*allp)])
    # per-scenario recall/FP diagnostics
    scen = {}
    for e, *ps in zip(evs, *allp):
        s = scen.setdefault(e["scenario"], {"n": 0, **{r[0]: 0 for r in rules}}); s["n"] += 1
        for (rid, *_), p in zip(rules, ps): s[rid] += int(p)
    res["by_scenario_alerts"] = scen
    print("\nalerts by scenario:"); [print(" ", k, v) for k, v in sorted(scen.items())]
    if a.out: Path(a.out).write_text(json.dumps(res, indent=2))
main()
