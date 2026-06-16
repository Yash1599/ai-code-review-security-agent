from app.security_rules import run_security_rules, calculate_risk_score


def test_detects_vulnerabilities():
    code = '''
password = "admin123"
query = f"SELECT * FROM users WHERE username = '{username}'"
eval(user_input)
os.system(command)
'''
    issues = run_security_rules(code)
    issue_types = {issue["issue_type"] for issue in issues}
    assert "Hardcoded Secret" in issue_types
    assert "Possible SQL Injection" in issue_types
    assert "Unsafe Dynamic Code Execution" in issue_types
    assert "Shell Command Injection Risk" in issue_types
    assert calculate_risk_score(issues) > 0


def test_detects_fintech_risks():
    code = '''
card_number = "4111111111111111"
print(f"cvv=123 account=123456789 iban=GB29NWBK60161331926819")
'''
    issues = run_security_rules(code)
    issue_types = {issue["issue_type"] for issue in issues}
    assert "Raw Payment Card Storage" in issue_types
    assert "Sensitive Financial Identifier Exposure" in issue_types
    assert "Unmasked Payment Log" in issue_types
