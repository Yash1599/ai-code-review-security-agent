from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_review_rules_only():
    payload = {
        "filename": "payments.py",
        "language": "python",
        "mode": "rules_only",
        "code": "card_number = '4111111111111111'\nprint(f'cvv=123 account=123456789')",
    }
    response = client.post("/review", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["total_issues"] >= 2
    assert body["risk_score"] > 0
    assert body["ai_review"] is None
    assert any(issue["issue_type"] in {"Raw Payment Card Storage", "Unmasked Payment Log"} for issue in body["issues"])


def test_review_ai_layer_present():
    payload = {
        "filename": "payments.py",
        "language": "python",
        "mode": "llm_assisted",
        "code": "card_number = '4111111111111111'\nprint(f'cvv=123 account=123456789')",
    }
    response = client.post("/review", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["ai_review"] is not None
    assert body["ai_review"]["summary"]
    assert body["ai_review"]["focus_areas"]
