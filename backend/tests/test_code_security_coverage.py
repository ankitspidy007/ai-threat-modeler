from app.engine.code_security import CodeSecurityAnalyzer


def test_every_occurrence_of_a_rule_is_reported():
    source = '\n'.join([
        'cur.execute("SELECT * FROM users WHERE id = " + user_id)',
        'cur.execute("SELECT * FROM orders WHERE ref = " + request.args["ref"])',
        'cur.execute("SELECT * FROM carts WHERE owner = " + owner)',
    ])

    findings = [
        finding for finding in CodeSecurityAnalyzer().analyze(source)
        if finding['rule_id'] == 'CODE-SQLI-DYNAMIC-QUERY'
    ]

    assert [finding['line'] for finding in findings] == [1, 2, 3]
    assert {finding['rule_match_count'] for finding in findings} == {3}


def test_findings_are_addressable_by_line():
    source = '\n'.join([
        'API_KEY = "very-secret-key-value"',
        'harmless = compute()',
        'DB_PASSWORD = "another-secret-value"',
    ])

    findings = [
        finding for finding in CodeSecurityAnalyzer().analyze(source)
        if finding['rule_id'] == 'CODE-HARDCODED-SECRET'
    ]

    assert [finding['line'] for finding in findings] == [1, 3]
    assert {finding['id'] for finding in findings} == {
        'CODE-HARDCODED-SECRET:1', 'CODE-HARDCODED-SECRET:3',
    }


def test_repeated_matches_are_capped_and_truncation_is_stated():
    line = 'cur.execute("SELECT * FROM t WHERE id = " + value)'
    source = '\n'.join([line] * (CodeSecurityAnalyzer.MAX_FINDINGS_PER_RULE + 5))

    findings = [
        finding for finding in CodeSecurityAnalyzer().analyze(source)
        if finding['rule_id'] == 'CODE-SQLI-DYNAMIC-QUERY'
    ]

    assert len(findings) == CodeSecurityAnalyzer.MAX_FINDINGS_PER_RULE
    assert findings[0]['truncated_matches'] == 5
    assert any('further matches' in item for item in findings[0]['evidence'])
