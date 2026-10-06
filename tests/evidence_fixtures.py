"""Valid model-response fixtures for API integration tests."""

from itertools import product

from ai_scoring import HARM_BASE_POINTS
from parser import parse_message


def evidence_payload(score, text="message", scam_type="Phishing", summary="Suspicious request"):
    if score > 100:
        levels = (5, 0, 0, 0)
    else:
        link_levels = range(3) if parse_message(text)["urls"] else [0]
        for levels in product(range(5), range(5), range(5), link_levels):
            harm, deception, pressure, link = levels
            total = HARM_BASE_POINTS[harm] + deception * 1.5 + pressure + link
            if int(total + 0.5) == score:
                break
        else:
            raise ValueError(f"No fixture rubric produces {score} for this text")
    return {
        "scam_type": scam_type,
        "ai_summary": summary,
        "risk_assessment": {
            name: {"level": level, "evidence": ["text:0"] if level else [], "reason": "Evidence in input"}
            for name, level in zip(("harm", "deception", "pressure", "link_risk"), levels)
        },
    }
