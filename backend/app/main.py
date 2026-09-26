from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.engine.risk_engine import RiskAnalyzer
from app.models.schemas import AnalyzeRequest, RiskReport

app = FastAPI(
    title="Context-Aware Digital Terms & Privacy Policy Threat Analyzer",
    description="API for analyzing privacy policies and terms of service for predatory clauses.",
    version="2.0.0"
)

# Configure CORS for the Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer = RiskAnalyzer()


@app.get("/health")
def health_check():
    return {"status": "ok", "message": "Threat Analyzer Engine is running.", "version": "2.0.0"}


@app.post("/analyze", response_model=RiskReport)
def analyze_policy(request: AnalyzeRequest):
    """Fast rule-based analysis. Does NOT call Gemini AI.
    Use /ai-summary for the AI-powered TL;DR summary."""
    try:
        report = analyzer.analyze(request.text)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


class AISummaryRequest(BaseModel):
    text: str


class AISummaryResponse(BaseModel):
    summary: str


@app.post("/ai-summary", response_model=AISummaryResponse)
def get_ai_summary(request: AISummaryRequest):
    """Call Google Gemini to generate a plain-English TL;DR of the policy.
    Requires GEMINI_API_KEY in the .env file."""
    try:
        summary = analyzer.get_ai_summary(request.text)
        return AISummaryResponse(summary=summary)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI summary failed: {str(e)}")
