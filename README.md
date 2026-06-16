# Corridor Fintech Security Review

A fintech-focused AI backend for reviewing payment, identity, and platform code.

It includes:

- FastAPI backend
- Rule-based application security scanner
- Optional LLM security review agent using OpenAI
- SQLite persistence for review history
- Evals/benchmarks endpoint
- Docker support
- Pytest tests
- Fintech-specific detections for PCI, PII, and payment logging risks

## Architecture

```text
Client / Swagger UI
        ↓
FastAPI /review endpoint
        ↓
Fintech-aware security engine
        ↓
Optional LLM review agent
        ↓
Risk score + structured findings
        ↓
SQLite review history
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Add your OpenAI key to `.env` if you want LLM review. The app still works without it.

```bash
OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-4.1-mini
```

## Run

```bash
python -m uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Test a Review

POST `/review`:

```json
{
  "filename": "vulnerable_code.py",
  "language": "python",
  "mode": "llm_assisted",
        "code": "card_number = '4111111111111111'\nprint(f'cvv=123 account=123456789')\nquery = f\"SELECT * FROM users WHERE username = '{username}'\"\neval(user_input)"
}
```

Use `"mode": "rules_only"` if you do not want to call the LLM.

Example fintech findings include PAN exposure, unmasked payment logs, SSN or account number leakage, SQL injection, unsafe deserialization, and dynamic code execution.

## Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/review` | Review code |
| GET | `/reviews` | List saved reviews |
| GET | `/reviews/{id}` | Read one saved review |
| POST | `/evals/run` | Run built-in evals |

## Run Tests

```bash
python -m pytest
```

## Docker

```bash
docker compose up --build
```

## Resume Bullets

```latex
        \resumeProjectHeading
{	\textbf{Corridor Fintech Security Review} $|$ \emph{Python, FastAPI, OpenAI API, SQLite, Docker, Pytest}}{}
\resumeItemListStart
\resumeItem{Built a production-style \textbf{fintech code review backend} that analyzes source code, detects risky patterns, calculates risk scores, and returns structured security findings through \textbf{FastAPI} endpoints.}
\resumeItem{Implemented deterministic security checks for \textbf{hardcoded secrets}, \textbf{PCI/PII exposure}, \textbf{SQL injection}, \textbf{unsafe eval/exec}, shell command execution, weak hashing, unsafe deserialization, and debug-mode exposure.}
\resumeItem{Integrated an optional \textbf{LLM review agent} with persistence, evals/benchmarks, Docker support, and regression tests to validate fintech security finding quality and production readiness.}
\resumeItemListEnd
```
