"""Layered PII recogniser: validated regexes + optional spaCy NER.

Layer 1  regex with checksum validators (EMAIL, URL, PHONE_NUM, ID_NUM, ADDRESS)
Layer 2  spaCy en_core_web_sm PERSON -> NAME (optional)
Layer 3  GLiNER (optional; NOT exercised in the build sandbox, see RESULTS.md)

USERNAME has no reliable surface form, so it is deliberately left to NER-style
models; the regex layer reports nothing for it.  That gap is measured, not hidden.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>\"')]+[A-Za-z0-9/_-]")
# Allow +1-, 001-, (###), separators . - space, optional extension x###
PHONE_RE = re.compile(
    r"(?<![\w.])(?:\+?\d{1,3}[-.\s])?(?:\(\d{3}\)\s?|\d{3}[-.\s])\d{3}[-.\s]\d{4}(?:\s?x\d{1,5})?(?!\w)")
SSN_RE = re.compile(r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
RIPE_RE = re.compile(r"\bORG-[A-Z0-9]{2,10}-RIPE\b")
ISBN13_RE = re.compile(r"\b97[89]-\d{1,5}-\d{1,7}-\d{1,7}-\d\b")
ISBN10_RE = re.compile(r"(?<![\w-])\d{1,5}-\d{1,7}-\d{1,7}-[\dX](?![\w-])")
SBN9_RE = re.compile(r"(?<![\w-])\d{1,3}-\d{4,6}-\d(?![\w-])")
DIGITS_RE = re.compile(r"(?<![\w.-])\d[\d -]{7,22}\d(?![\w-])")
BBAN_RE = re.compile(r"\b[A-Z]{4}\d{14}\b")
ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+[A-Z][a-z]+(?:\s[A-Z][a-z]+){1,2}(?:\s(?:Apt|Suite|Unit)\.?\s\d+)?\b")
TEN_DIGIT_RE = re.compile(r"(?<![\w.-])\d{10}(?![\w-])")


def luhn_ok(s: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if not 13 <= len(d) <= 19:
        return False
    tot = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        tot += n
    return tot % 10 == 0


def aba_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    if len(d) != 9:
        return False
    w = [3, 7, 1] * 3
    return sum(int(a) * b for a, b in zip(d, w)) % 10 == 0


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    r = s[4:] + s[:4]
    try:
        num = "".join(str(int(c, 36)) for c in r)
        return int(num) % 97 == 1
    except ValueError:
        return False


def isbn10_ok(s: str) -> bool:
    d = re.sub(r"[^0-9X]", "", s)
    if len(d) != 10:
        return False
    tot = sum((10 - i) * (10 if c == "X" else int(c)) for i, c in enumerate(d))
    return tot % 11 == 0


def isbn13_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    if len(d) != 13:
        return False
    tot = sum(int(c) * (1 if i % 2 == 0 else 3) for i, c in enumerate(d[:12]))
    return (10 - tot % 10) % 10 == int(d[12])


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    type: str
    source: str = "regex"


def regex_spans(text: str) -> list[Span]:
    out: list[Span] = []
    for m in EMAIL_RE.finditer(text):
        out.append(Span(m.start(), m.end(), "EMAIL"))
    for m in URL_RE.finditer(text):
        out.append(Span(m.start(), m.end(), "URL"))
    for m in PHONE_RE.finditer(text):
        out.append(Span(m.start(), m.end(), "PHONE_NUM"))
    for m in SSN_RE.finditer(text):
        out.append(Span(m.start(), m.end(), "ID_NUM"))
    for m in IBAN_RE.finditer(text):
        if iban_ok(m.group()):
            out.append(Span(m.start(), m.end(), "ID_NUM"))
    for m in RIPE_RE.finditer(text):
        out.append(Span(m.start(), m.end(), "ID_NUM"))
    for m in ISBN13_RE.finditer(text):
        if isbn13_ok(m.group()):
            out.append(Span(m.start(), m.end(), "ID_NUM"))
    for m in ISBN10_RE.finditer(text):  # Faker's isbn10 does not always pass the checksum
        out.append(Span(m.start(), m.end(), "ID_NUM"))
    for m in SBN9_RE.finditer(text):
        out.append(Span(m.start(), m.end(), "ID_NUM"))
    for m in TEN_DIGIT_RE.finditer(text):
        out.append(Span(m.start(), m.end(), "PHONE_NUM"))
    for m in BBAN_RE.finditer(text):
        out.append(Span(m.start(), m.end(), "ID_NUM"))
    for m in DIGITS_RE.finditer(text):
        s = m.group()
        if luhn_ok(s) or aba_ok(s):
            out.append(Span(m.start(), m.end(), "ID_NUM"))
        elif re.fullmatch(r"\d{12,13}", s):  # msisdn-like
            out.append(Span(m.start(), m.end(), "ID_NUM"))
    for m in ADDRESS_RE.finditer(text):
        out.append(Span(m.start(), m.end(), "ADDRESS"))
    return _dedupe(out)


def _dedupe(spans: list[Span]) -> list[Span]:
    """Drop spans nested inside a longer span (e.g. phone inside URL, email inside URL)."""
    spans = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    keep: list[Span] = []
    for s in spans:
        if any(k.start <= s.start and s.end <= k.end and k is not s for k in keep):
            continue
        keep.append(s)
    return keep


class Recogniser:
    def __init__(self, use_spacy: bool = True, use_gliner: bool = False):
        self.nlp = None
        self.gliner = None
        if use_spacy:
            import spacy
            self.nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer", "attribute_ruler"])
        if use_gliner:  # untested in sandbox
            from gliner import GLiNER  # type: ignore
            self.gliner = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")

    def spans(self, text: str) -> list[Span]:
        out = regex_spans(text)
        if self.nlp is not None:
            doc = self.nlp(text[:100_000])
            for e in doc.ents:
                if e.label_ == "PERSON":
                    out.append(Span(e.start_char, e.end_char, "NAME", "spacy"))
        if self.gliner is not None:
            labels = ["person", "username", "address", "phone number", "email", "id number"]
            m = {"person": "NAME", "username": "USERNAME", "address": "ADDRESS",
                 "phone number": "PHONE_NUM", "email": "EMAIL", "id number": "ID_NUM"}
            for e in self.gliner.predict_entities(text, labels, threshold=0.5):
                out.append(Span(e["start"], e["end"], m[e["label"]], "gliner"))
        return _dedupe(out)
