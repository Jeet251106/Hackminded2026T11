import re
from dataclasses import dataclass


@dataclass
class Detection:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float
    layer: str


REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AADHAAR", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
    ("PAN", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    ("PHONE", re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("UPI", re.compile(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b")),
    ("IFSC", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")),
    ("BANK_ACCOUNT", re.compile(r"\b\d{9,18}\b")),
    (
        "BIOMETRIC",
        re.compile(
            r"\b(fingerprint|thumbprint|iris(?:\s+scan)?|retina(?:\s+scan)?|face\s*id|facial\s+recognition|voice\s*print|biometric(?:\s+template|\s+data)?|dna\s+profile)\b",
            re.IGNORECASE,
        ),
    ),
]


def _regex_detect(text: str) -> list[Detection]:
    found: list[Detection] = []
    for entity_type, pattern in REGEX_PATTERNS:
        for match in pattern.finditer(text):
            found.append(
                Detection(
                    entity_type=entity_type,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=1.0,
                    layer="regex",
                )
            )
    return found


def _spacy_detect(text: str) -> list[Detection]:
    try:
        import spacy  # type: ignore
    except Exception:
        return []

    try:
        nlp = spacy.load("en_core_web_sm")
    except Exception:
        return []

    mapped = {
        "PERSON": "NAME",
        "ORG": "ORGANIZATION",
        "GPE": "ADDRESS",
        "LOC": "ADDRESS",
        "DATE": "DOB",
    }
    out: list[Detection] = []
    doc = nlp(text)
    for ent in doc.ents:
        entity_type = mapped.get(ent.label_)
        if not entity_type:
            continue
        out.append(
            Detection(
                entity_type=entity_type,
                value=ent.text,
                start=ent.start_char,
                end=ent.end_char,
                confidence=0.75,
                layer="spacy",
            )
        )
    return out


def _presidio_detect(text: str) -> list[Detection]:
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore
    except Exception:
        return []

    try:
        analyzer = AnalyzerEngine()
        results = analyzer.analyze(text=text, language="en")
    except Exception:
        return []

    mapped = {
        "PHONE_NUMBER": "PHONE",
        "EMAIL_ADDRESS": "EMAIL",
        "PERSON": "NAME",
        "IP_ADDRESS": "IP",
        "LOCATION": "ADDRESS",
        "CREDIT_CARD": "CARD_NUMBER",
    }
    out: list[Detection] = []
    for res in results:
        out.append(
            Detection(
                entity_type=mapped.get(res.entity_type, res.entity_type),
                value=text[res.start : res.end],
                start=res.start,
                end=res.end,
                confidence=float(res.score),
                layer="presidio",
            )
        )
    return out


def _dedupe(detections: list[Detection]) -> list[Detection]:
    best: dict[tuple[int, int, str], Detection] = {}
    for det in detections:
        key = (det.start, det.end, det.entity_type)
        if key not in best or det.confidence > best[key].confidence:
            best[key] = det
    return sorted(best.values(), key=lambda d: (d.start, d.end))


def detect_pii(text: str) -> list[Detection]:
    detections = []
    detections.extend(_regex_detect(text))
    detections.extend(_spacy_detect(text))
    detections.extend(_presidio_detect(text))
    return _dedupe(detections)
