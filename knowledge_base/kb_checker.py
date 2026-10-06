"""
Knowledge Base Checker Module for Scam Checker AI.
Compares text against known scam keywords and phrases across categories.
Modular design allows future integration of vector embeddings or semantic search.
"""

import json
import logging
import re
import unicodedata
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

KB_FILE_PATH = Path(__file__).resolve().parent / "scam_phrases.json"


class KBChecker:
    """
    Scam Knowledge Base Checker using categorized keyword/phrase matching.
    """

    def __init__(self, phrases_path: Path = KB_FILE_PATH):
        self.phrases_path = Path(phrases_path)
        self._signature = None
        self._reload()

    @staticmethod
    def _normalize(text: str) -> str:
        # Thai copy/paste can contain zero-width characters; NFKC also handles
        # full-width Latin characters and equivalent Thai vowel sequences.
        text = unicodedata.normalize("NFKC", text).casefold()
        return "".join(char for char in text if unicodedata.category(char) != "Cf")

    @classmethod
    def _compile_phrase(cls, phrase: str):
        compact = re.sub(r"\s+", "", cls._normalize(phrase))
        parts = []
        acronym_positions = set()
        for match in re.finditer(r"otp|pin|dsi", compact):
            acronym_positions.update(range(match.start() + 1, match.end()))
        for index, char in enumerate(compact):
            if index:
                previous = compact[index - 1]
                if index in acronym_positions:
                    parts.append(r"[\s.\-_]*")
                elif (previous.isascii() and previous.isalnum()) != (char.isascii() and char.isalnum()):
                    parts.append(r"[\s:\-]*")
                else:
                    parts.append(r"\s*")
            parts.append(re.escape(char))
        # Do not detect "dsi" inside "adsite", or 100 inside 1000.
        prefix = r"(?<![a-z0-9])" if compact[0].isascii() and compact[0].isalnum() else ""
        suffix = r"(?![a-z0-9])" if compact[-1].isascii() and compact[-1].isalnum() else ""
        return re.compile(prefix + "".join(parts) + suffix)

    def _file_signature(self):
        try:
            stat = self.phrases_path.stat()
            return (stat.st_mtime_ns, stat.st_size)
        except OSError:
            return None

    def _reload(self):
        self._signature = self._file_signature()
        self.phrases = self._load_phrases()
        self._patterns = {
            category: [(phrase, self._compile_phrase(phrase)) for phrase in phrases]
            for category, phrases in self.phrases.items()
        }

    def _refresh(self):
        if self._file_signature() != self._signature:
            self._reload()

    def _load_phrases(self) -> Dict[str, List[str]]:
        """Loads scam phrases from JSON file."""
        if not self.phrases_path.exists():
            logger.warning("Scam phrases file not found at: %s", self.phrases_path)
            return {}
        try:
            with open(self.phrases_path, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            if not isinstance(data, dict) or not data:
                raise ValueError("Knowledge Base must contain categorized phrases")
            validated = {}
            for category, phrases in data.items():
                if not isinstance(category, str) or not category.strip() or not isinstance(phrases, list):
                    raise ValueError("Invalid Knowledge Base category")
                if not phrases or any(not isinstance(p, str) or not self._normalize(p).strip() for p in phrases):
                    raise ValueError("Invalid Knowledge Base phrase")
                validated[category] = list(dict.fromkeys(phrases))
            return validated
        except Exception as e:
            logger.exception("Failed to load scam phrases from %s: %s", self.phrases_path, e)
            return {}

    def calculate_score(self, category_matches: Dict[str, List[str]]) -> int:
        """
        Calculates a risk score (0-100) based on matched categories and phrase density.

        Rules:
        - 0 categories: 0
        - 1 category: 30
        - 2 categories: 60
        - 3 categories: 80
        - 4 categories: 95
        - Bonus: If multiple phrases matched within categories, add bonus up to 100
        """
        matched_cats_count = len(category_matches)
        if matched_cats_count == 0:
            return 0

        base_scores = {
            1: 30,
            2: 60,
            3: 80,
            4: 95,
            5: 100,
        }
        score = base_scores.get(matched_cats_count, 100)

        total_phrases = sum(len(phrases) for phrases in category_matches.values())
        # Bonus for high phrase count
        if total_phrases >= 3:
            score += 10

        return min(100, score)

    def check(self, text: str) -> Dict[str, Any]:
        """
        Matches text against scam phrases.

        Args:
            text: Input text string to check.

        Returns:
            dict: {
                "matched_categories": list of matched category names,
                "matched_phrases": list of all matched phrases,
                "category_matches": dict mapping category to list of matched phrases,
                "kb_score": int (0-100)
            }
        """
        self._refresh()
        metadata = {
            "kb_status": "ready" if self.phrases else "unavailable",
            "phrase_count": sum(len(phrases) for phrases in self.phrases.values()),
        }
        if not text:
            return {
                "matched_categories": [],
                "matched_phrases": [],
                "category_matches": {},
                "kb_score": 0,
                **metadata,
            }

        normalized_text = self._normalize(text)

        category_matches: Dict[str, List[str]] = {}
        all_matched_phrases: List[str] = []

        for category, phrases in self._patterns.items():
            matched_in_cat = []
            for phrase, pattern in phrases:
                if pattern.search(normalized_text):
                    matched_in_cat.append(phrase)
                    if phrase not in all_matched_phrases:
                        all_matched_phrases.append(phrase)

            if matched_in_cat:
                category_matches[category] = matched_in_cat

        kb_score = self.calculate_score(category_matches)

        return {
            "matched_categories": list(category_matches.keys()),
            "matched_phrases": all_matched_phrases,
            "category_matches": category_matches,
            "kb_score": kb_score,
            **metadata,
        }


# Singleton instance for quick module access
_default_checker = KBChecker()


def check_knowledge_base(text: str) -> Dict[str, Any]:
    """
    Convenience wrapper to check text using the default KBChecker instance.
    """
    return _default_checker.check(text)


if __name__ == "__main__":
    sample_text = "ด่วนที่สุด! ธนาคารกรุงไทยแจ้งว่าคุณได้รับรางวัล กรุณาแจ้งรหัส OTP ภายใน 24 ชม."
    result = check_knowledge_base(sample_text)
    print("Sample:", sample_text)
    print("Matched Categories:", result["matched_categories"])
    print("Matched Phrases:", result["matched_phrases"])
    print("KB Score:", result["kb_score"])
