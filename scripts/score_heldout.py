"""One-shot held-out scoring. Refuses to run unless the frozen files and label hash verify,
and refuses to run a second time. Run from the repo root."""
import hashlib, json, subprocess, sys
from pathlib import Path

EV, LAB, OUT = Path("data/traffic/events_heldout.jsonl"), Path("data/traffic/heldout_labels.sha256"), Path("results/heldout_confusion.json")

def label_hash():
    evs = [json.loads(l) for l in open(EV)]
    return hashlib.sha256("".join(f"{e['event_id']}:{e['label']}" for e in evs).encode()).hexdigest(), len(evs)

if "--check-only" in sys.argv:
    h, n = label_hash(); ok = h == LAB.read_text().strip()
    print(f"label hash {'MATCHES' if ok else 'DOES NOT MATCH'} ({n} events)"); sys.exit(0 if ok else 1)

if OUT.exists():
    sys.exit(f"{OUT} already exists: held-out is scored once. Stopping.")
if subprocess.run(["sha256sum", "-c", "FREEZE.sha256"]).returncode:
    sys.exit("frozen files changed since the freeze. Stopping.")
h, n = label_hash()
if h != LAB.read_text().strip():
    sys.exit("held-out labels do not match the recorded hash. Stopping.")
print(f"frozen files verified; label hash matches ({n} events); scoring once")
enr = "data/traffic/events_heldout_enriched.jsonl"
subprocess.run([sys.executable, "scripts/enrich.py", str(EV), enr], check=True)
subprocess.run([sys.executable, "scripts/run_rules.py", enr, "--out", str(OUT)], check=True)
