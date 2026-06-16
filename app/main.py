from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from app.database import init_db, save_review, get_review, list_reviews
from app.evals import run_default_evals
from app.llm_agent import review_code_with_llm
from app.schemas import CodeReviewRequest, CodeReviewResponse, ReviewListItem, EvalRunResponse
from app.security_rules import run_security_rules, calculate_risk_score

app = FastAPI(
    title="Corridor Fintech Security Review",
    description="Fintech-focused rule-based security scanner with optional LLM review, evals, and review history.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/")
def root() -> dict:
    return {
        "status": "running",
        "service": "Corridor Fintech Security Review",
        "docs": "/docs",
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/review", response_model=CodeReviewResponse)
def review_code(request: CodeReviewRequest) -> CodeReviewResponse:
    issues = run_security_rules(request.code)
    risk_score = calculate_risk_score(issues)

    if request.mode == "rules_only":
        llm_summary = "Rules-only mode enabled. LLM review was skipped."
        ai_review = None
    else:
        ai_review = review_code_with_llm(
            filename=request.filename,
            language=request.language,
            code=request.code,
            rule_findings=issues,
        )
        llm_summary = ai_review["summary"]

    saved = save_review(
        filename=request.filename,
        language=request.language,
        mode=request.mode.value,
        code=request.code,
        issues=issues,
        llm_summary=llm_summary,
        ai_review=ai_review,
        risk_score=risk_score,
    )

    return CodeReviewResponse(
        id=saved["id"],
        filename=saved["filename"],
        language=saved["language"],
        mode=saved["mode"],
        risk_score=saved["risk_score"],
        total_issues=len(saved["issues"]),
        issues=saved["issues"],
        llm_summary=saved["llm_summary"],
        ai_review=saved.get("ai_review"),
        created_at=saved["created_at"],
    )


@app.get("/reviews", response_model=list[ReviewListItem])
def get_reviews(limit: int = Query(default=20, ge=1, le=100)) -> list[ReviewListItem]:
    return list_reviews(limit=limit)


@app.get("/reviews/{review_id}", response_model=CodeReviewResponse)
def get_review_by_id(review_id: int) -> CodeReviewResponse:
    saved = get_review(review_id)
    if not saved:
        raise HTTPException(status_code=404, detail="Review not found")
    return CodeReviewResponse(
        id=saved["id"],
        filename=saved["filename"],
        language=saved["language"],
        mode=saved["mode"],
        risk_score=saved["risk_score"],
        total_issues=len(saved["issues"]),
        issues=saved["issues"],
        llm_summary=saved["llm_summary"],
        ai_review=saved.get("ai_review"),
        created_at=saved["created_at"],
    )


@app.post("/evals/run", response_model=EvalRunResponse)
def run_evals() -> EvalRunResponse:
    return run_default_evals()
