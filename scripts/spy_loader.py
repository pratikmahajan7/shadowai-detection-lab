"""Rebuild the SPY PII dataset with character-level gold spans.

SPY (Savkin, Ionov & Konovalov, NAACL-SRW 2025) ships text with <TYPE>
placeholders; entity values are filled in at load time with Faker.  The
upstream loader (spy.py) needs `trust_remote_code`, so this module
re-implements the same substitution:

  * same Faker providers per entity type (copied from upstream spy.py)
  * one value per entity type per document, reused for repeated placeholders
    (upstream behaviour)
  * a pinned seed, recorded in the output, so the corpus is reproducible
  * character-level gold spans computed on the *reconstructed* text

Known differences from the Hugging Face loader (document these in the thesis):
  * value-to-document assignment differs (upstream shuffles columns globally;
    here each document draws from a seeded RNG), so entity values are not
    byte-identical to `load_dataset(..., faker_random_seed=0)`;
  * upstream `trailing_whitespaces` arrays do not match token counts in the
    raw files, so whitespace is taken from the tokens themselves.

Each document is assigned to a pool:
  tune     - small pool used to calibrate recogniser patterns
  heldout  - everything else; used for reported numbers and traffic synthesis
"""
from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

from faker import Faker

ENT_TYPES = ["NAME", "EMAIL", "PHONE_NUM", "ADDRESS", "URL", "USERNAME", "ID_NUM"]
PLACEHOLDER = re.compile(r"<(" + "|".join(ENT_TYPES) + r")>")
DOMAINS = {
    "legal_questions": "legal_questions_placeholders.jsonl",
    "medical_consultations": "medical_consultations_placeholders.jsonl",
}


def make_value_funcs(fake: Faker) -> dict:
    return {
        "EMAIL": [fake.ascii_email, fake.ascii_free_email],
        "NAME": [fake.name],
        "URL": [lambda: fake.uri(deep=1), lambda: fake.uri(deep=2)],
        "PHONE_NUM": [fake.phone_number],
        "ID_NUM": [
            fake.ripe_id, fake.msisdn, fake.ssn, fake.sbn9, fake.isbn10,
            fake.isbn13, fake.credit_card_number, fake.aba, fake.bban, fake.iban,
        ],
        "ADDRESS": [fake.street_address],
        "USERNAME": [fake.user_name],
    }


def build_document(row: dict, values: dict[str, str]) -> tuple[str, list[dict]]:
    """Return (text, entities) with entities as {start, end, type, text}."""
    parts: list[str] = []
    entities: list[dict] = []
    pos = 0
    toks, tags = row["tokens"], row["ent_tags"]
    for i, (tok, tag) in enumerate(zip(toks, tags)):
        m = PLACEHOLDER.search(tok) if tag.startswith("B-") else None
        if not m:
            parts.append(tok)
            pos += len(tok)
            continue
        etype = m.group(1)
        val = values[etype]
        prefix, suffix = tok[: m.start()], tok[m.end():]
        # Upstream tokens sometimes glue a placeholder to the next word
        # ("<PHONE_NUM>for"); keep a space so the text reads naturally.
        nxt = toks[i + 1] if i + 1 < len(toks) else ""
        if not suffix and nxt and nxt[0].isalnum():
            suffix = " "
        parts.append(prefix)
        pos += len(prefix)
        entities.append({"start": pos, "end": pos + len(val), "type": etype, "text": val})
        parts.append(val)
        pos += len(val)
        parts.append(suffix)
        pos += len(suffix)
    return "".join(parts), entities


def build_corpus(raw_dir: Path, seed: int, tune_fraction: float) -> list[dict]:
    fake = Faker()
    fake.seed_instance(seed)
    rng = random.Random(seed)
    funcs = make_value_funcs(fake)
    docs: list[dict] = []
    for domain, fname in DOMAINS.items():
        with open(raw_dir / fname, encoding="utf-8") as fh:
            for idx, line in enumerate(fh):
                row = json.loads(line)
                values = {t: rng.choice(funcs[t])() for t in ENT_TYPES}
                text, ents = build_document(row, values)
                docs.append({"id": f"{domain}-{idx:05d}", "domain": domain,
                             "text": text, "entities": ents, "seed": seed})
    order = list(range(len(docs)))
    random.Random(seed + 1).shuffle(order)
    n_tune = int(len(docs) * tune_fraction)
    for rank, i in enumerate(order):
        docs[i]["pool"] = "tune" if rank < n_tune else "heldout"
    return docs


def load_corpus(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raw-dir", default="data/spy_raw/repo/data")
    ap.add_argument("--out", default="data/spy_filled.jsonl")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--tune-fraction", type=float, default=0.15)
    args = ap.parse_args()
    docs = build_corpus(Path(args.raw_dir), args.seed, args.tune_fraction)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for d in docs:
            fh.write(json.dumps(d, ensure_ascii=False) + "\n")
    n_ent = sum(len(d["entities"]) for d in docs)
    pools = {p: sum(d["pool"] == p for d in docs) for p in ("tune", "heldout")}
    print(f"wrote {len(docs)} docs, {n_ent} gold entities, pools={pools}, seed={args.seed} -> {args.out}")


if __name__ == "__main__":
    main()
