"""
AIVI Campus OS - Document Preprocessor & Security Guard
Handles:
1. OCR Gating & Text Density Assessment (identifying scanned/zero-text PDFs)
2. Adversarial Prompt Injection Detection & Tagging
3. Multilingual Hinglish / Phonetic Terminology Normalization
"""

import re
import logging
from typing import List, Tuple
from .models import LegibilityStatus, InjectionRiskLevel, PreprocessReport

logger = logging.getLogger("AIVICampusOS.Preprocessor")

# Prompt injection signatures
INJECTION_PATTERNS = [
    (r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions", "Instruction Override"),
    (r"(?i)system\s+(prompt\s+)?override", "System Prompt Override"),
    (r"(?i)match_score\s*:\s*100", "Hardcoded Score Spoof"),
    (r"(?i)output\s+(only\s+)?the\s+following\s+json", "Output Schema Hijack"),
    (r"(?i)you\s+are\s+now\s+in\s+(developer|dan|admin)\s+mode", "Jailbreak Persona Switch"),
    (r"(?i)bypass\s+all\s+(rubrics|filters|evaluation)", "Safety Filter Bypass"),
    (r"(?i)candidate\s+is\s+(perfect|ideal|the\s+best)\s+hire\s+immediately", "Biased Direct Injection"),
]

# Phonetic & Hinglish tech term canonicalization map
HINGLISH_CANONICAL_MAP = [
    # Common transliterated / misspelled tech tools
    (r"\bpaython\b", "Python"),
    (r"\breddis\b", "Redis"),
    (r"\bdokar\b", "Docker"),
    (r"\bflusk\b", "Flask"),
    (r"\bpostgress?\b", "PostgreSQL"),
    (r"\bmongodb me\b", "in MongoDB"),
    (r"\bk8s\b", "Kubernetes"),
    (r"\bmern stack pe\b", "using MERN stack"),
    (r"\bfast\s*api\b", "FastAPI"),
    
    # Common conversational Hinglish phrases mapped to standard technical context
    (r"\bpe\s+kaam\s+kiya\s+(hai|tha)?\b", "experienced in"),
    (r"\bbanaya\s+(hai|tha)?\b", "developed"),
    (r"\bdeploy\s+kiya\s+(hai|tha)?\b", "deployed"),
    (r"\bhost\s+kiya\s+(hai|tha)?\b", "hosted"),
    (r"\bchhod\s+diya\b", "discontinued"),
    (r"\bsambhal\s+liya\b", "managed and took ownership of"),
    (r"\blatency\s+bohot\s+kam\s+ki\b", "substantially reduced latency"),
    (r"\bfatafat\s+kiya\b", "rapidly implemented"),
]


class DocumentPreProcessor:
    """Pre-processing engine for incoming resumes and text layers."""

    @staticmethod
    def assess_legibility(raw_text: str, min_char_threshold: int = 50) -> Tuple[LegibilityStatus, int]:
        """
        Assesses if the extracted text layer has sufficient character density
        or if it represents an un-OCRed scanned PDF / corrupted byte stream.
        """
        if not raw_text:
            return LegibilityStatus.EMPTY_INPUT, 0

        clean_chars = raw_text.strip()
        char_count = len(clean_chars)

        if char_count == 0:
            return LegibilityStatus.EMPTY_INPUT, 0

        # Check for unmapped font / garbage bytes (high frequency of replacement characters)
        replacement_count = clean_chars.count("\ufffd") + clean_chars.count("\x00")
        if char_count > 0 and (replacement_count / char_count) > 0.15:
            logger.warning("Corrupted byte stream detected in document text.")
            return LegibilityStatus.CORRUPTED_STREAM, char_count

        # Check for scanned PDF with zero/insufficient text layer
        if char_count < min_char_threshold:
            logger.warning(f"Text character count ({char_count}) is below minimum threshold ({min_char_threshold}). Likely image scan.")
            return LegibilityStatus.SCANNED_EMPTY_LAYER, char_count

        return LegibilityStatus.MACHINE_READABLE, char_count

    @staticmethod
    def detect_prompt_injection(raw_text: str) -> Tuple[InjectionRiskLevel, List[str]]:
        """
        Scans resume body for adversarial prompt injection signatures.
        """
        detected = []
        for pattern, label in INJECTION_PATTERNS:
            if re.search(pattern, raw_text):
                detected.append(label)

        if len(detected) >= 2:
            return InjectionRiskLevel.ATTACK_DETECTED, detected
        elif len(detected) == 1:
            return InjectionRiskLevel.SUSPICIOUS, detected
        else:
            return InjectionRiskLevel.CLEAN, []

    @staticmethod
    def normalize_multilingual(text: str) -> str:
        """
        Normalizes Romanized Hindi (Hinglish) code-switching and phonetic
        spelling distortions to standard professional English terminology.
        """
        normalized = text
        for pattern, replacement in HINGLISH_CANONICAL_MAP:
            normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)
        return normalized

    @classmethod
    def process(cls, raw_text: str) -> PreprocessReport:
        """
        Executes the complete preprocessing pipeline.
        """
        status, count = cls.assess_legibility(raw_text)
        risk_level, patterns = cls.detect_prompt_injection(raw_text)
        normalized = cls.normalize_multilingual(raw_text)

        return PreprocessReport(
            character_count=count,
            legibility_status=status,
            injection_risk=risk_level,
            detected_patterns=patterns,
            normalized_text=normalized
        )
