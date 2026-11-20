"""Replay generated events through the lab proxy so the whole pipeline is exercised
on the real capture path (client -> TLS-intercepting proxy -> capture log).

Each event becomes an HTTPS POST to its destination domain and path. The proxy
answers replay traffic itself (see proxy/capture.py), so nothing reaches the real
services. The event id travels in the User-Agent (shadowai-replay/evNNNNN) so
detections can later be joined back to ground truth.

Usage:
  python scripts/replay.py --limit 50            # small smoke test
  python scripts/replay.py --rate 10             # whole dev file, 10 events/s
"""
import argparse
import json
import sys
import time
from collections import Counter

import requests


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="data/traffic/events_dev.jsonl")
    ap.add_argument("--proxy", default="http://127.0.0.1:8080")
    ap.add_argument("--ca", default="proxy/mitmproxy-ca.pem")
    ap.add_argument("--limit", type=int, default=0, help="0 = all events")
    ap.add_argument("--rate", type=float, default=5.0, help="events per second, 0 = unthrottled")
    args = ap.parse_args()

    with open(args.events, encoding="utf-8") as f:
        events = [json.loads(line) for line in f]
    if args.limit:
        events = events[: args.limit]

    s = requests.Session()
    s.proxies = {"http": args.proxy, "https": args.proxy}
    s.verify = args.ca

    status = Counter()
    errors = []
    t0 = time.time()
    for i, e in enumerate(events, 1):
        url = f"https://{e['destination.domain']}{e['url.path']}"
        try:
            r = s.post(
                url,
                data=e["http.request.body.content"].encode("utf-8"),
                headers={"User-Agent": f"shadowai-replay/{e['event_id']}",
                         "Content-Type": "text/plain; charset=utf-8"},
                timeout=20,
            )
            status[r.status_code] += 1
        except requests.RequestException as ex:
            status["error"] += 1
            if len(errors) < 3:
                errors.append(f"{e['destination.domain']}: {type(ex).__name__}")
        if args.rate > 0:
            ahead = t0 + i / args.rate - time.time()
            if ahead > 0:
                time.sleep(ahead)
        if i % 50 == 0:
            print(f"sent {i}/{len(events)}", flush=True)

    print(f"done: {len(events)} events in {time.time() - t0:.0f}s, status counts: {dict(status)}")
    if errors:
        print("first errors:", errors, file=sys.stderr)


if __name__ == "__main__":
    main()
