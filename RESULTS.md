# Shadow-AI PII detection lab: first results (v0, dev split only)

Status 31 Oct 2026. Nothing here is a final number. Rules are v0 and have not been tuned.

## 1. PII recogniser on SPY (held-out pool, first 2,500 of 7,385 docs, 16,299 gold entities)
Regexes were calibrated on a separate 1,303-doc tuning pool. Overlap-match scores:

| Entity | Recall | Precision* | Notes |
|---|---|---|---|
| EMAIL | 1.000 | 0.361 | |
| PHONE_NUM | 1.000 | 0.432 | |
| URL | 1.000 | 0.439 | |
| ADDRESS | 1.000 (exact span 0.504) | 0.591 | generic "number + capitalised words" pattern |
| ID_NUM | 0.957 | 0.970 | checksums (Luhn, ABA, IBAN, ISBN) + format regexes |
| NAME (spaCy en_core_web_sm) | 0.960 | 0.242 | |
| USERNAME | 0.000 | n/a | no regex layer by design; needs a model (GLiNER, untested here) |
| Micro | 0.847 | 0.416 | |

*Precision is understated. SPY only labels the placeholder entities. The LLM-written text around them contains
unlabelled PII-looking strings (lawoffice.com, 555-123-4567, "John Thompson"), which score as false positives.
Treat the recall column as the reliable one; do not quote the precision column as the recogniser's real precision.

## 2. Detection rules on synthetic traffic (dev split: 1,683 events, 498 positives)
Positive = body contains gold PII AND destination is an unsanctioned GenAI endpoint.

| Rule | TP | FP | FN | Precision | Recall | F1 | FP / 1k benign |
|---|---|---|---|---|---|---|---|
| R1 known-AI domain + any PII | 266 | 180 | 232 | 0.596 | 0.534 | 0.564 | 151.9 |
| R2 known-AI domain + strong PII | 262 | 158 | 236 | 0.624 | 0.526 | 0.571 | 133.3 |
| R3 AI URL path + strong PII, not sanctioned | 485 | 330 | 13 | 0.595 | 0.974 | 0.739 | 278.5 |
| R4 AI URL path + 2+ PII types, not sanctioned | 440 | 206 | 58 | 0.681 | 0.884 | 0.769 | 173.8 |
| Union | 489 | 352 | 9 | 0.581 | 0.982 | 0.730 | 297.0 |

What the numbers say:
- Domain-list rules (R1, R2) reach about 53% recall because they miss every long-tail AI domain (scenario B: 0 of 232). The URL-path rules (R3, R4) recover it (225 and 197 of 232). This is the RQ1 finding so far.
- Neither sanctioned-gateway traffic (273 events) nor PII sent to ordinary SaaS (385 events) alerted, so the scoping logic works.
- False positives come from two places: PII-lookalikes (git URLs, example.com links count as URL/ADDRESS) and filler text in the no-PII scenario that the recogniser flags. R4's multi-type requirement cuts FPs most, at a recall cost.

## 3. Caveats
- Synthetic traffic, balanced scenario mix (about 30% positive). Real prevalence is far lower, so real-world precision would be lower than shown. Report FP per 1,000 benign events alongside precision.
- Only the dev split has been scored. 1,317 held-out events exist; their labels are hashed (data/traffic/heldout_labels.sha256) and unread. Freeze rules before scoring them.
- The ELK/AWS stage is not built. These results come from a Python Sigma evaluator, so MTTD (RQ3) is not measured.
- GLiNER backend is written but never run (model download blocked in the build sandbox).
- SPY has no LICENSE file; check terms before redistributing. Entity values differ from the Hugging Face loader at seed 0 (see spy_loader.py docstring).
- Only 2,500 of 7,385 held-out SPY docs were scored.

## 4. Next steps
1. Dev-only iteration on rules: drop URL from strong types, exclude example.com and git remotes, add a document-level threshold. Then freeze and score the held-out split once.
2. Run the same Sigma files through pySigma into Elastic queries on a small EC2 ELK, to measure ingestion-to-alert latency (RQ3).
3. Try GLiNER on EC2 or the local machine to cover USERNAME.

## Reproduce
spy_loader.py -> evaluate_pii_spy.py -> gen_traffic.py -> enrich.py -> run_rules.py (all under scripts/, seed 42 / 7).
