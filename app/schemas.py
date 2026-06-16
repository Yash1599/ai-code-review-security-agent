from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ReviewMode(str, Enum):
    RULES_ONLY = "rules_only"
    LLM_ASSISTED = "llm_assisted"


class CodeReviewRequest(BaseModel):
    filename: str = Field(..., examples=["app.py"])
    language: str = Field(..., examples=["python"])
    code: str = Field(..., min_length=1)
    mode: ReviewMode = ReviewMode.LLM_ASSISTED


class SecurityIssue(BaseModel):
    issue_type: str
    severity: Severity
    line_number: Optional[int]
    code_snippet: Optional[str] = None
    message: str
    recommendation: str
    confidence: float = Field(..., ge=0, le=1)
    source: str = Field(default="rule_engine")


class AIInsight(BaseModel):
    topic: str
    impact: str
    recommendation: str
    confidence: float = Field(..., ge=0, le=1)


class AIReview(BaseModel):
    summary: str
    risk_posture: str
    focus_areas: list[str]
    insights: list[AIInsight]
    next_steps: list[str]


class CodeReviewResponse(BaseModel):
    id: int
    filename: str
    language: str
    mode: ReviewMode
    risk_score: int = Field(..., ge=0, le=100)
    total_issues: int
    issues: list[SecurityIssue]
    llm_summary: str
    ai_review: Optional[AIReview] = None
    created_at: str


class ReviewListItem(BaseModel):
    id: int
    filename: str
    language: str
    total_issues: int
    risk_score: int
    created_at: str


class EvalCase(BaseModel):
    name: str
    filename: str
    language: str
    code: str
    expected_issue_types: list[str]


class EvalResult(BaseModel):
    case_name: str
    expected_issue_types: list[str]
    detected_issue_types: list[str]
    matched: list[str]
    missed: list[str]
    extra: list[str]
    precision: float
    recall: float


class EvalRunResponse(BaseModel):
    total_cases: int
    average_precision: float
    average_recall: float
    results: list[EvalResult]
