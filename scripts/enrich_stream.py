"""Enrichment stage: read the mitmproxy capture log, add PII and domain-category
fields, write an enriched JSONL file that the shipper sends to Elasticsearch.

Design choices worth defending in the thesis:
  * Only PII *types and counts* are stored, never the matched values, so the
    detection index does not become a second copy of the sensitive data.
  * domain_category emulates a proxy vendor's category list: a few well-known
    GenAI domains are labelled, everything else AI-related stays unlabelled.
    That gap is the recall problem the URL-path rules are meant to close.
  * shadowai.enriched_at records when enrichment finished; together with the
    capture @timestamp it gives the first leg of the MTTD measurement.

Usage:
  python scripts/enrich_stream.py                 # process existing lines, exit
  python scripts/enrich_stream.py --follow        # keep tailing for new lines
"""
import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pii_recogniser import Recogniser  # noqa: E402

KNOWN_AI = {"chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com", "perplexity.ai",
            "copilot.microsoft.com", "chat.mistral.ai", "grok.com"}
SANCTIONED = {"ai-gateway.corp.example.com"}
BUSINESS_SAAS = {"acme.my.salesforce.com", "acme.workday.com", "acme.zendesk.com",
                 "files.corp-sharepoint.example", "docs.google.com", "slack.com",
                 "notion.so", "github.com", "stackoverflow.com"}
STRONG = {"EMAIL", "PHONE_NUM", "ID_NUM", "URL", "ADDRESS"}  # NAME comes from NER only
EVENT_ID = re.compile(r"shadowai-replay/(ev\d+)")


def category(domain: str) -> str:
    if domain in KNOWN_AI:
        return "Generative AI"
    if domain in SANCTIONED:
        return "Corporate AI"
    if domain in BUSINESS_SAAS:
        return "Business/SaaS"
    return "Uncategorized"


def enrich(rec: dict, engine: Recogniser) -> dict:
    body = (((rec.get("http") or {}).get("request") or {}).get("body") or {}).get("content") or ""
    spans = engine.spans(body)
    types = sorted({s.type for s in spans})
    rec["pii"] = {
        "count": len(spans),
        "types": types,
        "types_distinct": len(types),
        "strong_count": sum(s.type in STRONG for s in spans),
    }
    domain = (rec.get("destination") or {}).get("domain") or ""
    rec["domain_category"] = category(domain)
    shadow = {"enriched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"}
    m = EVENT_ID.search((rec.get("user_agent") or {}).get("original") or "")
    if m:
        shadow["event_id"] = m.group(1)
    rec["shadowai"] = shadow
    return rec


def read_lines(path: Path, follow: bool):
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
            f.seek(pos)  # writer is mid-line, or nothing new yet
            time.sleep(0.3)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="logs/genai-traffic.jsonl")
    ap.add_argument("--out", default="logs/genai-enriched.jsonl")
    ap.add_argument("--follow", action="store_true")
    args = ap.parse_args()

    engine = Recogniser(use_spacy=True)
    n = 0
    with open(args.out, "a", encoding="utf-8") as out:
        for line in read_lines(Path(args.src), args.follow):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                print("skipping malformed line", file=sys.stderr)
                continue
            out.write(json.dumps(enrich(rec, engine), ensure_ascii=False) + "\n")
            out.flush()
            n += 1
            if n % 50 == 0:
                print(f"enriched {n}", flush=True)
    print(f"done, enriched {n}")


if __name__ == "__main__":
    main()
