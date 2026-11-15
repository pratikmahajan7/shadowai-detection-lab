# Shadow-AI PII detection lab: results

Status 15 Nov 2026. Rules and recogniser are frozen (git tag `rules-frozen-v1`, hashes in `FREEZE.sha256`).
The held-out split was scored once (tag `heldout-scored-v1`).

## 1. PII recogniser on SPY (held-out pool, first 2,500 of 7,385 docs, 16,299 gold entities)
Regexes were calibrated on a separate 1,303-doc tuning pool. Overlap-match scores, measured before the
reserved-value filter described in section 2:

| Entity | Recall | Precision* | Notes |
|---|---|---|---|
| EMAIL | 1.000 | 0.361 | |
| PHONE_NUM | 1.000 | 0.432 | |
| URL | 1.000 | 0.439 | |
| ADDRESS | 1.000 (exact span 0.504) | 0.591 | generic "number + capitalised words" pattern |
| ID_NUM | 0.957 | 0.970 | checksums (Luhn, ABA, IBAN, ISBN) plus format regexes |
| NAME (spaCy en_core_web_sm) | 0.960 | 0.242 | |
| USERNAME | 0.000 | n/a | no regex layer by design; needs a model (GLiNER, not run) |
| Micro | 0.847 | 0.416 | |

*Precision is understated. SPY labels only the placeholder entities, so PII-looking strings elsewhere in the
LLM-written text count as false positives. Treat recall as the reliable column.

## 2. Detection rules on synthetic traffic
Positive = body contains gold PII and the destination is an unsanctioned GenAI endpoint.
Dev split: 1,683 events, 498 positive. Held-out split: 1,317 events, 383 positive.

The only change after v0 was one filter in the recogniser: values that cannot identify a real person
(RFC 2606 names such as example.com, localhost, 127.0.0.1, the 555-01xx phone block) are no longer reported.
On the tuning pool it left recall unchanged and reduced EMAIL, PHONE and URL predictions. On dev it cut false
positives for R3 from 330 to 232 and lost one true positive.

| Rule | Dev P | Dev R | Held-out TP | FP | FN | TN | P | R | F1 | FP per 1k benign |
|---|---|---|---|---|---|---|---|---|---|---|
| R1 known-AI domain + any PII | 0.635 | 0.534 | 201 | 114 | 182 | 820 | 0.638 | 0.525 | 0.576 | 122.1 |
| R2 known-AI domain + strong PII | 0.697 | 0.526 | 198 | 84 | 185 | 850 | 0.702 | 0.517 | 0.595 | 89.9 |
| R3 AI URL path + strong PII, not sanctioned | 0.676 | 0.972 | 370 | 175 | 13 | 759 | 0.679 | 0.966 | 0.797 | 187.4 |
| R4 AI URL path + 2+ PII types, not sanctioned | 0.757 | 0.882 | 338 | 117 | 45 | 817 | 0.743 | 0.883 | 0.807 | 125.3 |
| Union | 0.643 | 0.980 | 373 | 205 | 10 | 729 | 0.645 | 0.974 | 0.776 | 219.5 |

What the numbers say:
- RQ1. Domain-list rules (R1, R2) reach about 52% recall because they miss every long-tail AI domain. On held-out
  scenario B (181 long-tail positives) R1 and R2 caught 0; R3 caught 173 and R4 157.
- RQ2. R4 has the best precision (0.74) at 0.88 recall. R3 has the best recall (0.97) at 0.68 precision.
  The union reaches 0.97 recall at the cost of 219.5 false positives per 1,000 benign events.
- Scoping works: sanctioned-gateway traffic and PII sent to ordinary SaaS never alerted, on either split.
- Dev and held-out agree to within about two points, as expected with a shared generator (see caveats).
- Remaining false positives come from the no-PII scenario (SPY text with the gold spans replaced, which still
  contains real-looking values) and from lookalike snippets such as ssh remotes.

## 3. Elasticsearch pipeline check
The same Sigma files were converted with pySigma and deployed to Kibana as custom-query detection rules.
On the dev events (recogniser v1) the confusion matrix computed inside Elasticsearch matched the Python reference
evaluator for every rule, and Kibana alert counts equalled TP + FP (R1 446, R2 420, R3 815, R4 646).
A live run of 60 events produced exactly the 104 expected alerts.

## 4. Time to detection (RQ3)
Five live runs of 120 events at 3 events per second, 880 alerts in total. Time is measured from the proxy
capture timestamp to the alert timestamp.

| Stage | Median (s) | p95 (s) | Max (s) |
|---|---|---|---|
| Capture to enriched | 0.18 | 0.32 | 0.35 |
| Enriched to shipped | 0.20 | 0.30 | 0.34 |
| Shipped to alert | 32.71 | 56.48 | 59.98 |
| **Capture to alert** | **33.11** | **56.79** | **60.12** |

By rule, capture to alert median: R1 32.5 s, R2 32.1 s, R3 33.7 s, R4 34.1 s.
Two earlier runs gave medians of 48.9 s (60 events in a 12 s burst) and 30.9 s (120 events over 40 s).

Detection time is set by the rules' one-minute schedule. The pipeline legs add about 0.4 s. An event waits for
the next rule run, so the delay is roughly uniform over 0 to 60 s, with a median near 30 s and a maximum just
over the interval. Shortening the rule interval is the lever; Kibana's minimum schedule interval limits how far.

## 5. Caveats
- Synthetic traffic with a balanced scenario mix (about 30% positive). Real prevalence is far lower, so real-world
  precision would be lower. Quote false positives per 1,000 benign events next to precision.
- Dev and held-out come from the same generator and templates. Their agreement shows the rules were not fitted to
  individual dev events. It does not show that they generalise to real traffic.
- The reserved-value filter targets values that the generator's lookalike scenario uses, so part of the gain on both
  splits comes from that shared design.
- The no-PII scenario contains residual PII-looking values, so some counted false positives are label noise.
- Held-out scoring followed a freeze protocol: file hashes recorded, label hash verified, result written once.
- Alerts are not independent: alerts from one event share a capture time and alerts from one rule run share an alert
  time. The MTTD sample is alerts pooled across five runs on a single instance, with a local proxy and no network delay.
- USERNAME is not detected (GLiNER was not run). SPY has no LICENSE file; check terms before redistributing.
- Only 2,500 of 7,385 held-out SPY documents were scored for the recogniser.

## 6. Reproduce
`spy_loader.py` -> `evaluate_pii_spy.py` -> `gen_traffic.py` -> `enrich.py` -> `run_rules.py` (reference evaluator,
under scripts/, seeds 42 and 7). Elastic path: `convert_rules.py` -> `deploy_rules.py` -> `replay.py` through the
proxy -> `enrich_stream.py` -> `ship_to_es.py` -> `evaluate_es.py`; live demo with `scripts/live_demo.sh 120 3` and
`measure_mttd.py`. Held-out: `score_heldout.py`, one run only.
