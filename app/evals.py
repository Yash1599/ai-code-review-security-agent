from app.schemas import EvalCase, EvalResult, EvalRunResponse
from app.security_rules import run_security_rules

DEFAULT_EVAL_CASES = [
    EvalCase(
        name="python_secrets_sql_eval",
        filename="vulnerable.py",
        language="python",
        code='''import os\npassword = "admin123"\nquery = f"SELECT * FROM users WHERE name = '{name}'"\neval(user_input)\nos.system(cmd)''',
        expected_issue_types=["Hardcoded Secret", "Possible SQL Injection", "Unsafe Dynamic Code Execution", "Shell Command Injection Risk"],
    ),
    EvalCase(
        name="python_weak_hash_debug",
        filename="app.py",
        language="python",
        code='''import hashlib\napp.run(debug=True)\nhashlib.md5(password.encode()).hexdigest()''',
        expected_issue_types=["Insecure Debug Mode", "Weak Hashing Algorithm"],
    ),
    EvalCase(
        name="fintech_card_and_logging",
        filename="payments.py",
        language="python",
        code='''card_number = "4111111111111111"\nprint(f"charging {card_number} cvv=123")\nlogger.info(f"iban={iban} account={account_number}")''',
        expected_issue_types=["Raw Payment Card Storage", "Sensitive Financial Identifier Exposure", "Unmasked Payment Log"],
    ),
]


def _score(expected: set[str], detected: set[str]) -> tuple[float, float]:
    if not detected:
        precision = 1.0 if not expected else 0.0
    else:
        precision = len(expected & detected) / len(detected)
    recall = 1.0 if not expected else len(expected & detected) / len(expected)
    return round(precision, 3), round(recall, 3)


def run_default_evals() -> EvalRunResponse:
    results = []
    for case in DEFAULT_EVAL_CASES:
        issues = run_security_rules(case.code)
        expected = set(case.expected_issue_types)
        detected = {issue["issue_type"] for issue in issues}
        precision, recall = _score(expected, detected)
        results.append(EvalResult(
            case_name=case.name,
            expected_issue_types=sorted(expected),
            detected_issue_types=sorted(detected),
            matched=sorted(expected & detected),
            missed=sorted(expected - detected),
            extra=sorted(detected - expected),
            precision=precision,
            recall=recall,
        ))
    avg_precision = round(sum(r.precision for r in results) / len(results), 3)
    avg_recall = round(sum(r.recall for r in results) / len(results), 3)
    return EvalRunResponse(total_cases=len(results), average_precision=avg_precision, average_recall=avg_recall, results=results)
