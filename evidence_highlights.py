"""Map validated quotations onto exact source text, without changing scoring."""

from ai_scoring import FACTOR_LABELS


def build_highlights(text, ai_result):
    """Return text segments rather than Unicode offsets for browser rendering."""
    annotations, matches, unmatched = [], [], []
    assessment = ai_result.get("risk_assessment", {})
    if ai_result.get("analysis_status") == "unavailable":
        assessment = {}
    for factor, label in FACTOR_LABELS.items():
        item = assessment.get(factor) or {}
        if not isinstance(item.get("level"), int) or item["level"] <= 0:
            continue
        for quote in dict.fromkeys(item.get("evidence", [])):
            if not isinstance(quote, str) or not quote:
                continue
            positions, start = [], 0
            while True:
                start = text.find(quote, start)
                if start < 0:
                    break
                positions.append((start, start + len(quote)))
                start += 1
            record = {"id": f"e{len(annotations)}", "factor": factor, "label": label,
                      "quote": quote, "level": item["level"], "reason": item.get("reason", ""),
                      "occurrences": len(positions)}
            annotations.append(record)
            if not positions:
                unmatched.append(record["id"])
            matches.extend((a, b, record["id"]) for a, b in positions)
    boundaries = sorted({0, len(text), *(p for a, b, _ in matches for p in (a, b))})
    segments = []
    for a, b in zip(boundaries, boundaries[1:]):
        ids = sorted({ref for left, right, ref in matches if left <= a and b <= right})
        if segments and segments[-1]["evidence_ids"] == ids:
            segments[-1]["text"] += text[a:b]
        else:
            segments.append({"text": text[a:b], "evidence_ids": ids})
    return {"segments": segments, "annotations": annotations, "unmatched": unmatched}
