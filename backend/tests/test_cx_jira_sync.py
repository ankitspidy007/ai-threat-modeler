from app.services.cx_jira_sync import (
    JiraIssue,
    SyncConfig,
    build_group_key,
    group_findings,
    normalize_cx_finding,
    sync_cx_findings_to_jira,
)


class FakeCxClient:
    def __init__(self, findings):
        self.findings = findings

    def fetch_findings(self):
        return self.findings


class FakeJiraClient:
    def __init__(self, existing=None):
        self.existing = existing or {}
        self.created = []
        self.updated = []
        self.comments = []
        self.reopened = []

    def find_issue_by_cx_group_key(self, group_key):
        return self.existing.get(group_key)

    def create_issue(self, payload):
        issue = JiraIssue(
            key=f"SEC-{len(self.created) + 1}",
            status="Open",
            summary=payload["summary"],
        )
        self.created.append(payload)
        return issue

    def update_issue(self, issue_key, payload):
        self.updated.append((issue_key, payload))

    def add_comment(self, issue_key, comment):
        self.comments.append((issue_key, comment))

    def reopen_issue(self, issue_key):
        self.reopened.append(issue_key)


def test_groups_multiple_findings_into_one_jira_issue():
    findings = [
        {
            "id": "1",
            "projectName": "payments",
            "branchName": "main",
            "queryName": "SQL Injection",
            "severity": "High",
            "cwe": "CWE-89",
            "filePath": "api/orders.py",
            "line": 10,
            "scanId": "scan-1",
        },
        {
            "id": "2",
            "projectName": "payments",
            "branchName": "main",
            "queryName": "SQL Injection",
            "severity": "High",
            "cwe": "CWE-89",
            "filePath": "api/refunds.py",
            "line": 20,
            "scanId": "scan-1",
        },
    ]
    jira = FakeJiraClient()

    result = sync_cx_findings_to_jira(
        FakeCxClient(findings),
        jira,
        SyncConfig(jira_project_key="SEC"),
    )

    assert result.fetched == 2
    assert result.groups == 1
    assert result.created == ["SEC-1"]
    assert result.duplicates_avoided == 0
    assert len(jira.created) == 1
    assert jira.created[0]["cx_occurrence_count"] == 2
    assert len(jira.created[0]["cx_finding_keys"]) == 2


def test_existing_group_updates_jira_issue_instead_of_creating_duplicate():
    raw_finding = {
        "id": "1",
        "projectName": "payments",
        "branchName": "main",
        "queryName": "Hardcoded Secret",
        "severity": "Critical",
        "cwe": "CWE-798",
        "filePath": "api/settings.py",
        "line": 7,
        "scanId": "scan-2",
    }
    config = SyncConfig(jira_project_key="SEC")
    finding = normalize_cx_finding(raw_finding)
    group_key = build_group_key(finding, config)
    jira = FakeJiraClient(
        existing={
            group_key: JiraIssue(
                key="SEC-44",
                status="Resolved",
                summary="[Cx][Critical] Hardcoded Secret in api",
            )
        }
    )

    result = sync_cx_findings_to_jira(
        FakeCxClient([raw_finding]),
        jira,
        config,
    )

    assert result.created == []
    assert result.updated == ["SEC-44"]
    assert result.duplicates_avoided == 1
    assert len(jira.updated) == 1
    assert jira.comments[0][0] == "SEC-44"
    assert jira.reopened == ["SEC-44"]


def test_low_severity_and_false_positive_findings_are_skipped():
    findings = [
        {
            "id": "1",
            "projectName": "payments",
            "queryName": "Verbose Error",
            "severity": "Low",
            "filePath": "api/orders.py",
        },
        {
            "id": "2",
            "projectName": "payments",
            "queryName": "XSS",
            "severity": "High",
            "status": "False Positive",
            "filePath": "web/profile.jsx",
        },
    ]

    result = sync_cx_findings_to_jira(
        FakeCxClient(findings),
        FakeJiraClient(),
        SyncConfig(jira_project_key="SEC"),
    )

    assert result.fetched == 2
    assert result.skipped == 2
    assert result.groups == 0
    assert result.created == []


def test_grouping_can_ignore_component_when_configured():
    config = SyncConfig(jira_project_key="SEC", group_by_component=False)
    findings = [
        normalize_cx_finding(
            {
                "id": "1",
                "projectName": "payments",
                "queryName": "XSS",
                "severity": "High",
                "cwe": "CWE-79",
                "filePath": "web/profile.jsx",
            }
        ),
        normalize_cx_finding(
            {
                "id": "2",
                "projectName": "payments",
                "queryName": "XSS",
                "severity": "High",
                "cwe": "CWE-79",
                "filePath": "admin/users.jsx",
            }
        ),
    ]

    groups = group_findings(findings, config)

    assert len(groups) == 1
    assert groups[0].component == "all-components"
