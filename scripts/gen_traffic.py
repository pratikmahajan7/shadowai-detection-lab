"""Generate labelled synthetic proxy-style events from SPY held-out-pool documents.

Truth definition: positive == body carries gold PII (SPY span) AND destination is an
unsanctioned GenAI endpoint.  Scenario mix is a design parameter, not a prevalence estimate.
"""
import argparse, hashlib, json, random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from spy_loader import load_corpus

KNOWN_AI = ["chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com", "perplexity.ai",
            "copilot.microsoft.com", "chat.mistral.ai", "grok.com"]
LONG_TAIL_AI = ["chat.deepseek.com", "poe.com", "you.com", "kimi.com", "chat.qwen.ai", "notesage-ai.io",
                "quickdraft-assistant.app", "legalbuddy-gpt.com", "medchat-helper.ai", "summarizr.dev"]
SANCTIONED = ["ai-gateway.corp.example.com"]
CORP_SAAS = ["acme.my.salesforce.com", "acme.workday.com", "acme.zendesk.com", "files.corp-sharepoint.example"]
GENERIC_SAAS = ["docs.google.com", "slack.com", "notion.so", "github.com", "stackoverflow.com"]
AI_PATHS = ["/backend-api/conversation", "/api/chat", "/v1/chat/completions", "/api/generate", "/chat/send", "/api/ask"]
WEB_PATHS = ["/api/save", "/submit", "/upload", "/api/v2/records", "/graphql"]
LOOKALIKE = [
    "git clone git@github.com:acme/payments-service.git then run npm i",
    "upgrade from 3.11.2 to 3.12.0 and pin numpy==1.26.4",
    "error id 550e8400-e29b-41d4-a716-446655440000 at 10.0.12.7:8443 build 20260930",
    "contact support@example.com or call 555-0100 for the demo tenant",
    "SELECT user_id, created_at FROM orders WHERE total > 100 ORDER BY 2 DESC",
    "docker pull ghcr.io/acme/api:2.4.1 && kubectl rollout status deploy/api",
    "see https://docs.example.com/guide#install and set API_BASE=http://localhost:8080",
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 matches",
]
CATEGORY = {d: "Generative AI" for d in KNOWN_AI}
CATEGORY.update({d: "Uncategorized" for d in LONG_TAIL_AI})   # emulates domain-list recall gap
CATEGORY.update({d: "Corporate AI" for d in SANCTIONED})

def snippet(doc, rng, strip=False):
    t = doc["text"]
    ents = sorted(doc["entities"], key=lambda e: e["start"])
    if not ents: return None
    i = rng.randrange(len(ents))
    mid = ents[i]["start"]
    a = max(0, mid - rng.randint(100, 500)); b = min(len(t), a + rng.randint(400, 1400))
    sub, gold = t[a:b], [e for e in ents if e["start"] >= a and e["end"] <= b]
    if strip:   # replace gold PII with neutral words; text still carries LLM-written filler
        for e in sorted(gold, key=lambda e: -e["start"]):
            sub = sub[:e["start"]-a] + "the client" + sub[e["end"]-a:]
        gold = []
    return sub, gold

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out-dir", default="data/traffic")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    docs = [d for d in load_corpus(Path("data/spy_filled.jsonl")) if d["pool"] == "heldout" and d["entities"]]
    users = [f"user{u:03d}" for u in range(60)]
    mix = [("A_pii_knownAI", .17), ("B_pii_longtailAI", .13), ("C_pii_sanctioned", .15), ("D_nopii_AI", .17),
           ("E_lookalike_AI", .13), ("F_pii_corpSaaS", .15), ("G_pii_genericSaaS", .10)]
    names = [m[0] for m in mix]; w = [m[1] for m in mix]
    evs = []
    for k in range(a.n):
        sc = rng.choices(names, w)[0]; doc = rng.choice(docs)
        if sc == "A_pii_knownAI": dom, path, (body, gold) = rng.choice(KNOWN_AI), rng.choice(AI_PATHS), snippet(doc, rng)
        elif sc == "B_pii_longtailAI": dom, path, (body, gold) = rng.choice(LONG_TAIL_AI), rng.choice(AI_PATHS), snippet(doc, rng)
        elif sc == "C_pii_sanctioned": dom, path, (body, gold) = rng.choice(SANCTIONED), rng.choice(AI_PATHS), snippet(doc, rng)
        elif sc == "D_nopii_AI": dom, path, (body, gold) = rng.choice(KNOWN_AI + LONG_TAIL_AI), rng.choice(AI_PATHS), snippet(doc, rng, strip=True)
        elif sc == "E_lookalike_AI": dom, path, body, gold = rng.choice(KNOWN_AI + LONG_TAIL_AI), rng.choice(AI_PATHS), " ".join(rng.sample(LOOKALIKE, 3)), []
        elif sc == "F_pii_corpSaaS": dom, path, (body, gold) = rng.choice(CORP_SAAS), rng.choice(WEB_PATHS), snippet(doc, rng)
        else: dom, path, (body, gold) = rng.choice(GENERIC_SAAS), rng.choice(WEB_PATHS), snippet(doc, rng)
        unsanctioned_ai = dom in KNOWN_AI or dom in LONG_TAIL_AI
        label = int(bool(gold) and unsanctioned_ai)
        uid = rng.choice(users)
        split = "heldout" if int(hashlib.sha1(uid.encode()).hexdigest(), 16) % 10 < 4 else "dev"
        evs.append({"event_id": f"ev{k:05d}", "split": split, "scenario": sc, "user.name": uid,
                    "destination.domain": dom, "url.path": path, "http.request.method": "POST",
                    "domain_category": CATEGORY.get(dom, "Business/SaaS"),
                    "http.request.body.content": body, "label": label,
                    "gold_types": sorted({e["type"] for e in gold})})
    out = Path(a.out_dir); out.mkdir(parents=True, exist_ok=True)
    for sp in ("dev", "heldout"):
        sel = [e for e in evs if e["split"] == sp]
        (out / f"events_{sp}.jsonl").write_text("\n".join(json.dumps(e) for e in sel) + "\n")
        print(sp, len(sel), "positives", sum(e["label"] for e in sel))
    # pre-register the held-out labels: hash only, labels stay unread until rules are frozen
    h = hashlib.sha256("".join(f"{e['event_id']}:{e['label']}" for e in evs if e["split"] == "heldout").encode()).hexdigest()
    (out / "heldout_labels.sha256").write_text(h + "\n")
    print("heldout label hash", h)
main()
