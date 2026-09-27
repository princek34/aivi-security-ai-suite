"""
AIVI Campus OS - Data Models and Schema Definitions
Pydantic v2 schemas for resume evaluation, pre-processing, and placement ranking.
"""

import re
import logging
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("AIVICampusOS.Models")


class LegibilityStatus(str, Enum):
    """Document text layer legibility classifications."""
    MACHINE_READABLE = "MACHINE_READABLE"
    SCANNED_EMPTY_LAYER = "SCANNED_EMPTY_LAYER"
    CORRUPTED_STREAM = "CORRUPTED_STREAM"
    EMPTY_INPUT = "EMPTY_INPUT"


class InjectionRiskLevel(str, Enum):
    """Prompt injection risk rating."""
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK_DETECTED = "ATTACK_DETECTED"


class PreprocessReport(BaseModel):
    """Result of document pre-processing, OCR gating, and injection scanning."""
    character_count: int = Field(..., description="Total extracted character length")
    legibility_status: LegibilityStatus = Field(..., description="Document legibility grade")
    injection_risk: InjectionRiskLevel = Field(..., description="Detected prompt injection severity")
    detected_patterns: List[str] = Field(default_factory=list, description="Adversarial markers identified")
    normalized_text: str = Field(..., description="Sanitized, normalized candidate text")


class ResumeMatchResult(BaseModel):
    """
    Structured schema representing the automated match assessment
    between a candidate resume and a target job description.
    """
    match_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Deterministic qualification match score from 0 to 100."
    )
    top_strengths: List[str] = Field(
        ...,
        max_length=5,
        description="Up to 5 concrete skills or experiences verified in the resume matching the JD."
    )
    missing_skills: List[str] = Field(
        ...,
        max_length=5,
        description="Up to 5 critical skills or qualifications required by JD but absent in resume."
    )
    summary: str = Field(
        ...,
        description="Concise evaluation summary consisting of exactly two sentences."
    )

    @field_validator("summary")
    @classmethod
    def validate_two_sentences(cls, v: str) -> str:
        """
        Validates that the summary contains approximately 2 sentences.
        Splits by terminal sentence punctuation (. ! ?) and strips whitespace.
        """
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Summary field cannot be empty.")

        sentences = [s.strip() for s in re.split(r'[.!?]+(?:\s+|$)', trimmed) if s.strip()]
        if len(sentences) != 2:
            logger.warning(
                f"Summary sentence count check detected {len(sentences)} sentence(s) instead of 2: '{v}'"
            )
        return trimmed


class CandidateInput(BaseModel):
    """Input payload for a single candidate evaluation."""
    candidate_id: str = Field(default="cand_001", description="Unique student or applicant identifier")
    name: Optional[str] = Field(default="Candidate", description="Applicant full name")
    resume_text: str = Field(..., description="Raw extracted resume text")


class JobDescriptionInput(BaseModel):
    """Target job description payload."""
    job_id: str = Field(default="job_001", description="Unique placement drive job identifier")
    title: str = Field(..., description="Job role title")
    jd_text: str = Field(..., description="Detailed requirements and job description")


class EvaluationResponse(BaseModel):
    """Complete evaluation report for a candidate."""
    candidate_id: str
    name: str
    status: str
    match_result: Optional[ResumeMatchResult] = None
    preprocessing: PreprocessReport
    error_message: Optional[str] = None


class BatchEvaluationResponse(BaseModel):
    """Aggregated batch placement evaluation leaderboard."""
    job_id: str
    total_candidates: int
    evaluated_count: int
    average_score: float
    leaderboard: List[Dict[str, Any]]
    evaluations: List[EvaluationResponse]
