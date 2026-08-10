from app.engine.code_security import CodeSecurityAnalyzer


def test_detects_high_signal_web_and_authentication_vulnerabilities():
    source = '''
app.get('/users/:id', (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
  element.innerHTML = req.body.comment
  const isAdmin = req.body.isAdmin
  res.cookie('sid', token, { httpOnly: false, secure: false })
  exec(`convert ${req.query.file}`)
})
'''
    rule_ids = {finding['rule_id'] for finding in CodeSecurityAnalyzer().analyze(source)}

    assert 'CODE-SQLI-DYNAMIC-QUERY' in rule_ids
    assert 'CODE-XSS-DANGEROUS-SINK' in rule_ids
    assert 'CODE-AUTHZ-CLIENT-ROLE' in rule_ids
    assert 'CODE-SESSION-INSECURE-COOKIE' in rule_ids
    assert 'CODE-COMMAND-INJECTION' in rule_ids


def test_detects_ssrf_deserialization_and_hardcoded_secrets():
    source = '''
value = pickle.loads(request.data)
response = requests.get(request.args['url'])
API_KEY = "very-secret-key-value"
'''
    rule_ids = {finding['rule_id'] for finding in CodeSecurityAnalyzer().analyze(source)}

    assert {'CODE-UNSAFE-DESERIALIZATION', 'CODE-SSRF-REQUEST-URL', 'CODE-HARDCODED-SECRET'} <= rule_ids
