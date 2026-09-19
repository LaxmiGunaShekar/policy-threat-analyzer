"""Pydantic data models for risk analysis results."""

from pydantic import BaseModel, Field


class RiskMatch(BaseModel):
    """A single matched risky clause in the policy text."""
    rule_id: str = Field(description="Unique rule identifier")
    category: str = Field(description="Risk category name")
    severity: str = Field(description="Severity level: red, yellow, or green")
    severity_label: str = Field(description="Human-readable severity label")
    matched_text: str = Field(description="The exact text that matched the rule")
    context_snippet: str = Field(description="Surrounding text for context (up to 200 chars)")
    description: str = Field(description="Plain-English explanation of the risk")
    recommendation: str = Field(description="What the user should do")


class SeverityCounts(BaseModel):
    """Count of matches by severity level."""
    red: int = 0
    yellow: int = 0
    green: int = 0


class RiskReport(BaseModel):
    """Complete risk analysis report for a policy document."""
    total_matches: int = Field(description="Total number of risky clauses found")
    overall_risk_score: int = Field(
        ge=0, le=100,
        description="Weighted risk score from 0 (safe) to 100 (dangerous)"
    )
    risk_level: str = Field(description="Overall risk level: safe, caution, or dangerous")
    severity_counts: SeverityCounts = Field(description="Breakdown of matches by severity")
    matches: list[RiskMatch] = Field(
        default_factory=list,
        description="List of all matched risky clauses with details"
    )
    summary: str = Field(
        default="",
        description="Auto-generated plain-English summary of key findings"
    )


class AnalyzeRequest(BaseModel):
    """Payload for the /analyze endpoint."""
    text: str = Field(..., description="The privacy policy or terms of service text to analyze.")
    url: str | None = Field(default=None, description="Optional URL where the text was found.")
