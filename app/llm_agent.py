import json
from typing import Any
from app.config import OPENAI_API_KEY, OPENAI_MODEL
from app.schemas import AIInsight, AIReview


def local_summary(filename: str, issues: list[dict]) -> str:
    if not issues:
        return f"No rule-based security issues were detected in {filename}. This does not guarantee the code is secure; deeper review and tests are still recommended, especially for PCI, PII, and payment flows."
    critical = sum(1 for i in issues if i.get("severity") == "Critical")
    high = sum(1 for i in issues if i.get("severity") == "High")
    medium = sum(1 for i in issues if i.get("severity") == "Medium")
    types = sorted({i.get("issue_type", "Unknown") for i in issues})
    return (
        f"Fintech review for {filename}: detected {len(issues)} issue(s), including "
        f"{critical} critical, {high} high, and {medium} medium severity finding(s). "
        f"Main categories: {', '.join(types)}. Prioritize critical/high issues first, "
        f"replace unsafe patterns with validated APIs, and add regression tests after remediation. "
        f"Verify PCI DSS, data masking, and audit logging controls before release."
    )


def _risk_posture(issues: list[dict]) -> str:
    if any(issue.get("severity") == "Critical" for issue in issues):
        return "critical"
    if any(issue.get("severity") == "High" for issue in issues):
        return "elevated"
    if any(issue.get("severity") == "Medium" for issue in issues):
        return "moderate"
    return "low"


def _focus_areas(issues: list[dict]) -> list[str]:
    issue_types = {issue.get("issue_type", "") for issue in issues}
    areas = []
    if {"Raw Payment Card Storage", "Sensitive Financial Identifier Exposure", "Unmasked Payment Log"} & issue_types:
        areas.append("PCI DSS and sensitive-data handling")
    if "Possible SQL Injection" in issue_types:
        areas.append("parameterized data access")
    if "Unsafe Dynamic Code Execution" in issue_types:
        areas.append("runtime code execution safety")
    if "Unsafe Deserialization" in issue_types:
        areas.append("trusted deserialization boundaries")
    if "Hardcoded Secret" in issue_types:
        areas.append("secret management")
    if not areas:
        areas.append("secure-by-default engineering")
    return areas


def _fallback_ai_review(filename: str, issues: list[dict]) -> dict[str, Any]:
    summary = local_summary(filename, issues)
    insights = [
        AIInsight(
            topic=issue.get("issue_type", "Unknown"),
            impact=issue.get("message", "Review required."),
            recommendation=issue.get("recommendation", "Validate the remediation."),
            confidence=float(issue.get("confidence", 0.8)),
        ).model_dump()
        for issue in issues[:5]
    ]
    if not insights:
        insights = []
    next_steps = [
        "Add regression tests for any payment or identity data paths.",
        "Validate logs, traces, and alerts for sensitive-data exposure.",
    ]
    if any(issue.get("severity") in {"Critical", "High"} for issue in issues):
        next_steps.insert(0, "Prioritize remediation of critical and high-severity findings before release.")
    return AIReview(
        summary=summary,
        risk_posture=_risk_posture(issues),
        focus_areas=_focus_areas(issues),
        insights=insights,
        next_steps=next_steps,
    ).model_dump()


def _coerce_ai_review(raw: Any, fallback: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return fallback
    try:
        return AIReview.model_validate(raw).model_dump()
    except Exception:
        return fallback


def review_code_with_llm(filename: str, language: str, code: str, rule_findings: list[dict]) -> dict[str, Any]:
    """Optional LLM layer. App remains functional without OPENAI_API_KEY."""
    fallback = _fallback_ai_review(filename, rule_findings)
    if not OPENAI_API_KEY:
        return fallback

    try:
        from openai import OpenAI

        client = OpenAI(api_key=OPENAI_API_KEY)
        prompt = f"""
You are a senior application security engineer reviewing fintech software for PCI, PII, fraud, and reliability risks.

Review this code using the rule findings as grounded evidence. Do not invent vulnerabilities.
Focus on:
1. Security risk
2. Backend reliability and auditability risk
3. Safe remediation steps for fintech environments
4. Tests/evals that should be added

Return a valid JSON object with exactly these keys:
summary (string), risk_posture (string), focus_areas (array of strings), insights (array of objects with topic, impact, recommendation, confidence), next_steps (array of strings).
Use only the provided findings and code. Do not add extra keys.

Filename: {filename}
Language: {language}
Rule findings JSON:
{json.dumps(rule_findings, indent=2)}

Code:
```{language}
{code}
```
"""
        response = client.responses.create(
            model=OPENAI_MODEL,
            input=prompt,
        )
        content = response.output_text.strip()
        parsed = json.loads(content)
        return _coerce_ai_review(parsed, fallback)
    except Exception as exc:  # Keep backend usable even when model call fails.
        failure_review = dict(fallback)
        failure_review["summary"] = fallback["summary"] + f" LLM review unavailable: {exc}"
        return failure_review
