import re
from dataclasses import dataclass
from typing import Callable
from app.schemas import Severity


@dataclass(frozen=True)
class Rule:
    issue_type: str
    severity: Severity
    pattern: re.Pattern
    message: str
    recommendation: str
    confidence: float = 0.9


RULES: list[Rule] = [
    Rule(
        issue_type="Hardcoded Secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"(?i)(password|passwd|api[_-]?key|secret|token)\s*=\s*['\"][^'\"]{4,}['\"]"),
        message="Possible hardcoded credential or secret found.",
        recommendation="Move secrets to environment variables or a managed secret store such as AWS Secrets Manager.",
        confidence=0.86,
    ),
    Rule(
        issue_type="Unsafe Dynamic Code Execution",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(eval|exec)\s*\("),
        message="Code executes dynamic input, which can lead to arbitrary code execution.",
        recommendation="Avoid eval/exec. Use safe parsers, allowlists, or explicit function dispatch.",
        confidence=0.95,
    ),
    Rule(
        issue_type="Shell Command Injection Risk",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(os\.system|subprocess\.Popen|subprocess\.call|subprocess\.run)\s*\("),
        message="Shell command execution can be dangerous when user input reaches the command.",
        recommendation="Avoid shell=True, pass arguments as a list, validate inputs, and use safer library APIs when possible.",
        confidence=0.82,
    ),
    Rule(
        issue_type="Insecure Debug Mode",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"(?i)(debug\s*=\s*True|app\.run\([^\n]*debug\s*=\s*True)"),
        message="Debug mode appears to be enabled.",
        recommendation="Disable debug mode in production and configure environment-specific settings.",
        confidence=0.85,
    ),
    Rule(
        issue_type="Weak Hashing Algorithm",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\b(hashlib\.(md5|sha1)|createHash\(['\"](md5|sha1)['\"]\))"),
        message="Weak hashing algorithm detected.",
        recommendation="Use SHA-256 or stronger for non-password hashing, and bcrypt/argon2/scrypt for passwords.",
        confidence=0.9,
    ),
    Rule(
        issue_type="Unsafe Deserialization",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(pickle\.loads|pickle\.load|yaml\.load\s*\()"),
        message="Unsafe deserialization can execute attacker-controlled payloads.",
        recommendation="Avoid pickle for untrusted data. Use safe formats like JSON or yaml.safe_load where appropriate.",
        confidence=0.88,
    ),
    Rule(
        issue_type="Raw Payment Card Storage",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"(?i)\b(card_number|pan|credit_card|cardNumber)\b\s*[:=]\s*['\"][0-9\s-]{12,}['\"]"),
        message="Primary account number or card data appears to be stored directly in code.",
        recommendation="Never store raw PAN or card data in source or logs. Tokenize, encrypt, and use PCI-compliant vaults.",
        confidence=0.94,
    ),
    Rule(
        issue_type="Sensitive Financial Identifier Exposure",
        severity=Severity.HIGH,
        pattern=re.compile(r"(?i)\b(ssn|social_security|routing_number|account_number|iban|swift|bic|cvv|cvc)\b"),
        message="Sensitive financial or identity data may be exposed in code or identifiers.",
        recommendation="Treat financial identifiers as regulated data. Mask, tokenize, and restrict access using least privilege.",
        confidence=0.84,
    ),
    Rule(
        issue_type="Unmasked Payment Log",
        severity=Severity.HIGH,
        pattern=re.compile(r"(?i)\b(print|logger\.(info|warning|error|debug))\s*\(.*(card|pan|cvv|ssn|iban|account)"),
        message="Potential payment or PII data appears to be logged without masking.",
        recommendation="Redact payment and identity fields before logging; keep audit logs separate from sensitive payloads.",
        confidence=0.83,
    ),
]


def _line_number_for_index(code: str, index: int) -> int:
    return code.count("\n", 0, index) + 1


def _line_text(code: str, line_number: int) -> str:
    lines = code.splitlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""


def check_sql_injection(code: str) -> list[dict]:
    issues = []
    sql_keywords = re.compile(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b")
    risky_building = re.compile(r"(f['\"]|\.format\(|\+\s*\w+|%\s*\w+)" )
    for i, line in enumerate(code.splitlines(), start=1):
        if sql_keywords.search(line) and risky_building.search(line):
            issues.append({
                "issue_type": "Possible SQL Injection",
                "severity": Severity.CRITICAL.value,
                "line_number": i,
                "code_snippet": line.strip(),
                "message": "SQL query appears to be built with string interpolation or concatenation.",
                "recommendation": "Use parameterized queries or ORM query builders instead of interpolating user input.",
                "confidence": 0.9,
                "source": "rule_engine",
            })
    return issues


def run_security_rules(code: str) -> list[dict]:
    issues: list[dict] = []

    for rule in RULES:
        for match in rule.pattern.finditer(code):
            line_number = _line_number_for_index(code, match.start())
            issues.append({
                "issue_type": rule.issue_type,
                "severity": rule.severity.value,
                "line_number": line_number,
                "code_snippet": _line_text(code, line_number),
                "message": rule.message,
                "recommendation": rule.recommendation,
                "confidence": rule.confidence,
                "source": "rule_engine",
            })

    issues.extend(check_sql_injection(code))

    # De-duplicate identical issue type + line number combinations.
    seen = set()
    deduped = []
    for issue in issues:
        key = (issue["issue_type"], issue.get("line_number"), issue.get("code_snippet"))
        if key not in seen:
            seen.add(key)
            deduped.append(issue)
    return deduped


def calculate_risk_score(issues: list[dict]) -> int:
    weights = {"Low": 5, "Medium": 12, "High": 22, "Critical": 35}
    score = sum(weights.get(issue.get("severity"), 0) for issue in issues)
    return min(score, 100)
