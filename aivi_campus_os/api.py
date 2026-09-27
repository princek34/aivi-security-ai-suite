"""
AIVI Campus OS - FastAPI REST Service
Exposes endpoints for single evaluations, batch campus drives, and document legibility audits.
"""

from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from .models import (
    CandidateInput,
    JobDescriptionInput,
    EvaluationResponse,
    BatchEvaluationResponse,
    PreprocessReport,
    ResumeMatchResult
)
from .preprocessor import DocumentPreProcessor
from .matcher import evaluate_resume

app = FastAPI(
    title="AIVI Campus OS - Placement Matching API",
    description="AI Resume-Parsing, Placement Ranking, and Security-Guarded Evaluation Service",
    version="1.0.0"
)


class SingleEvaluationRequest(BaseModel):
    candidate: CandidateInput
    job_description: JobDescriptionInput
    gemini_api_key: str = Field(default="", description="Optional Gemini API key for live inference")


class BatchEvaluationRequest(BaseModel):
    candidates: List[CandidateInput]
    job_description: JobDescriptionInput
    gemini_api_key: str = Field(default="", description="Optional Gemini API key for live inference")


class DocumentScanRequest(BaseModel):
    raw_text: str = Field(..., description="Extracted resume text to audit")


@app.get("/health", tags=["Monitoring"])
def health_check():
    return {
        "status": "healthy",
        "service": "AIVI Campus OS",
        "engine_version": "1.0.0",
        "schema": "Pydantic v2"
    }


@app.post("/scan-document", response_model=PreprocessReport, tags=["Security & Preprocessing"])
def scan_document(request: DocumentScanRequest):
    """
    Performs OCR gating, character density verification, and prompt injection detection
    without invoking the full scoring engine.
    """
    return DocumentPreProcessor.process(request.raw_text)


@app.post("/evaluate", response_model=EvaluationResponse, tags=["Evaluation"])
def evaluate_single(request: SingleEvaluationRequest):
    """
    Evaluates a single candidate resume against a job description.
    """
    try:
        match_result, prep_report = evaluate_resume(
            resume_text=request.candidate.resume_text,
            jd_text=request.job_description.jd_text,
            api_key=request.gemini_api_key or None
        )

        return EvaluationResponse(
            candidate_id=request.candidate.candidate_id,
            name=request.candidate.name or "Candidate",
            status="SUCCESS",
            match_result=match_result,
            preprocessing=prep_report
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evaluation failed: {str(e)}"
        )


@app.post("/batch-evaluate", response_model=BatchEvaluationResponse, tags=["Evaluation"])
def batch_evaluate(request: BatchEvaluationRequest):
    """
    Evaluates a batch of campus resumes against a single job description,
    producing a ranked leaderboard.
    """
    evaluations: List[EvaluationResponse] = []
    leaderboard: List[Dict[str, Any]] = []

    for cand in request.candidates:
        match_result, prep_report = evaluate_resume(
            resume_text=cand.resume_text,
            jd_text=request.job_description.jd_text,
            api_key=request.gemini_api_key or None
        )

        score = match_result.match_score if match_result else 0
        eval_resp = EvaluationResponse(
            candidate_id=cand.candidate_id,
            name=cand.name or "Candidate",
            status="SUCCESS",
            match_result=match_result,
            preprocessing=prep_report
        )
        evaluations.append(eval_resp)

        leaderboard.append({
            "candidate_id": cand.candidate_id,
            "name": cand.name or "Candidate",
            "match_score": score,
            "injection_risk": prep_report.injection_risk.value,
            "legibility": prep_report.legibility_status.value
        })

    # Sort leaderboard by descending match_score
    leaderboard.sort(key=lambda x: x["match_score"], reverse=True)
    avg_score = sum(item["match_score"] for item in leaderboard) / len(leaderboard) if leaderboard else 0.0

    return BatchEvaluationResponse(
        job_id=request.job_description.job_id,
        total_candidates=len(request.candidates),
        evaluated_count=len(evaluations),
        average_score=round(avg_score, 2),
        leaderboard=leaderboard,
        evaluations=evaluations
    )
