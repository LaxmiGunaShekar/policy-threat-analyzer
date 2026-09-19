from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.engine.risk_engine import RiskAnalyzer
from app.models.schemas import AnalyzeRequest, RiskReport

app = FastAPI(
    title="Context-Aware Digital Terms & Privacy Policy Threat Analyzer",
    description="API for analyzing privacy policies and terms of service for predatory clauses.",
    version="1.0.0"
)

# Configure CORS for the Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to extension ID or specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer = RiskAnalyzer()

@app.get("/health")
def health_check():
    return {"status": "ok", "message": "Threat Analyzer Engine is running."}

@app.post("/analyze", response_model=RiskReport)
def analyze_policy(request: AnalyzeRequest):
    try:
        # Run the text through our risk engine
        report = analyzer.analyze(request.text)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

