"""Main logic for raising Checkmarx findings into Jira.

The API calls are intentionally represented as protocols so this module can be
used with real Checkmarx/Jira clients, mocks, or tests without changing the
dedupe and grouping behavior.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence


SEVERITY_ORDER = {
    "informational": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class CxFinding:
    """Normalized Checkmarx finding used by the sync logic."""

    finding_id: str
    project: str
    branch: str
    query_name: str
    severity: str
    cwe: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    source: Optional[str] = None
    sink: Optional[str] = None
    component: Optional[str] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    status: Optional[str] = None
    scan_id: Optional[str] = None
    cx_url: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FindingGroup:
    """A group of Cx findings that should map to one Jira issue."""

    group_key: str
    project: str
    branch: str
    query_name: str
    cwe: str
    severity: str
    component: str
    findings: Sequence[CxFinding]


@dataclass(frozen=True)
class JiraIssue:
    key: str
    status: str
    summary: str


@dataclass(frozen=True)
class SyncConfig:
    jira_project_key: str
    issue_type: str = "Bug"
    min_severity: str = "High"
    group_by_component: bool = True
    reopen_resolved_duplicates: bool = True
    label_prefix: str = "cx"


@dataclass
class SyncResult:
    fetched: int = 0
    skipped: int = 0
    groups: int = 0
    created: List[str] = field(default_factory=list)
    updated: List[str] = field(default_factory=list)
    duplicates_avoided: int = 0


class CxClient(Protocol):
    def fetch_findings(self) -> Sequence[Dict[str, Any]]:
        """Return raw findings from Checkmarx."""


class JiraClient(Protocol):
    def find_issue_by_cx_group_key(self, group_key: str) -> Optional[JiraIssue]:
        """Return an existing Jira issue for the Cx group key, if one exists."""

    def create_issue(self, payload: Dict[str, Any]) -> JiraIssue:
        """Create a Jira issue and return the created issue."""

    def update_issue(self, issue_key: str, payload: Dict[str, Any]) -> None:
        """Update an existing Jira issue."""

    def add_comment(self, issue_key: str, comment: str) -> None:
        """Add an audit comment to an existing Jira issue."""

    def reopen_issue(self, issue_key: str) -> None:
        """Reopen a resolved issue when the vulnerability reappears."""


def sync_cx_findings_to_jira(
    cx_client: CxClient,
    jira_client: JiraClient,
    config: SyncConfig,
) -> SyncResult:
    """Fetch Cx findings, group them, avoid duplicates, and raise Jira issues."""

    raw_findings = cx_client.fetch_findings()
    result = SyncResult(fetched=len(raw_findings))

    normalized = [normalize_cx_finding(item) for item in raw_findings]
    eligible_findings = [
        finding for finding in normalized if should_raise_finding(finding, config)
    ]
    result.skipped = len(normalized) - len(eligible_findings)

    groups = group_findings(eligible_findings, config)
    result.groups = len(groups)

    for group in groups:
        existing_issue = jira_client.find_issue_by_cx_group_key(group.group_key)
        payload = build_jira_payload(group, config)

        if existing_issue:
            result.duplicates_avoided += len(group.findings)
            jira_client.update_issue(existing_issue.key, payload)
            jira_client.add_comment(
                existing_issue.key,
                build_update_comment(group),
            )

            if (
                config.reopen_resolved_duplicates
                and existing_issue.status.lower() in {"done", "closed", "resolved"}
            ):
                jira_client.reopen_issue(existing_issue.key)

            result.updated.append(existing_issue.key)
            continue

        created_issue = jira_client.create_issue(payload)
        result.created.append(created_issue.key)

    return result


def normalize_cx_finding(raw: Dict[str, Any]) -> CxFinding:
    """Normalize common Cx/CxOne field names into the structure used here."""

    return CxFinding(
        finding_id=str(first_present(raw, "finding_id", "id", "resultId", default="")),
        project=str(first_present(raw, "project", "projectName", default="")),
        branch=str(first_present(raw, "branch", "branchName", default="main")),
        query_name=str(first_present(raw, "query_name", "queryName", "name", default="")),
        severity=str(first_present(raw, "severity", "risk", default="Medium")),
        cwe=optional_str(first_present(raw, "cwe", "cweId")),
        file_path=optional_str(first_present(raw, "file_path", "filePath", "path")),
        line_number=optional_int(first_present(raw, "line_number", "line", "lineNumber")),
        source=optional_str(first_present(raw, "source", "sourceNode")),
        sink=optional_str(first_present(raw, "sink", "sinkNode")),
        component=optional_str(first_present(raw, "component", "service", "module")),
        description=optional_str(first_present(raw, "description", "desc")),
        recommendation=optional_str(first_present(raw, "recommendation", "remediation")),
        status=optional_str(first_present(raw, "status", "state")),
        scan_id=optional_str(first_present(raw, "scan_id", "scanId")),
        cx_url=optional_str(first_present(raw, "cx_url", "url", "deepLink")),
        raw=raw,
    )


def should_raise_finding(finding: CxFinding, config: SyncConfig) -> bool:
    status = (finding.status or "").strip().lower()
    if status in {"false positive", "not exploitable", "resolved", "ignored"}:
        return False

    return severity_rank(finding.severity) >= severity_rank(config.min_severity)


def group_findings(
    findings: Iterable[CxFinding],
    config: SyncConfig,
) -> List[FindingGroup]:
    grouped: Dict[str, List[CxFinding]] = defaultdict(list)

    for finding in findings:
        grouped[build_group_key(finding, config)].append(finding)

    groups: List[FindingGroup] = []
    for group_key, group_findings_list in grouped.items():
        first = group_findings_list[0]
        groups.append(
            FindingGroup(
                group_key=group_key,
                project=first.project,
                branch=first.branch,
                query_name=first.query_name,
                cwe=first.cwe or "unknown-cwe",
                severity=max_severity(finding.severity for finding in group_findings_list),
                component=component_for(first, config),
                findings=tuple(group_findings_list),
            )
        )

    return sorted(groups, key=lambda item: item.group_key)


def build_group_key(finding: CxFinding, config: SyncConfig) -> str:
    key_parts = [
        "cx-group",
        finding.project,
        finding.branch,
        component_for(finding, config),
        finding.query_name,
        finding.cwe or "unknown-cwe",
    ]
    digest = stable_hash(key_parts)
    return f"cx-group:{digest}"


def build_finding_key(finding: CxFinding) -> str:
    key_parts = [
        "cx-finding",
        finding.project,
        finding.branch,
        finding.query_name,
        finding.cwe or "unknown-cwe",
        finding.file_path or "unknown-file",
        str(finding.line_number or ""),
        finding.source or "",
        finding.sink or "",
    ]
    digest = stable_hash(key_parts)
    return f"cx-finding:{digest}"


def build_jira_payload(group: FindingGroup, config: SyncConfig) -> Dict[str, Any]:
    labels = [
        "checkmarx",
        "security",
        f"{config.label_prefix}-{group.severity.lower()}",
        normalize_label(group.cwe),
    ]

    return {
        "project": {"key": config.jira_project_key},
        "issuetype": {"name": config.issue_type},
        "summary": build_summary(group),
        "description": build_description(group),
        "labels": sorted(set(labels)),
        "cx_group_key": group.group_key,
        "cx_finding_keys": [build_finding_key(finding) for finding in group.findings],
        "cx_occurrence_count": len(group.findings),
        "cx_severity": group.severity,
        "cx_project": group.project,
        "cx_branch": group.branch,
        "cx_cwe": group.cwe,
    }


def build_summary(group: FindingGroup) -> str:
    component_text = "" if group.component == "unknown-component" else f" in {group.component}"
    return f"[Cx][{group.severity}] {group.query_name}{component_text}"


def build_description(group: FindingGroup) -> str:
    lines = [
        f"*Cx group key:* {group.group_key}",
        f"*Project:* {group.project}",
        f"*Branch:* {group.branch}",
        f"*Component:* {group.component}",
        f"*Severity:* {group.severity}",
        f"*CWE:* {group.cwe}",
        f"*Query:* {group.query_name}",
        f"*Occurrences:* {len(group.findings)}",
        "",
        "*Affected locations:*",
    ]

    for finding in group.findings:
        location = finding.file_path or "unknown file"
        if finding.line_number:
            location = f"{location}:{finding.line_number}"
        lines.append(f"- {location} | key={build_finding_key(finding)}")

    recommendations = unique_values(
        finding.recommendation for finding in group.findings if finding.recommendation
    )
    if recommendations:
        lines.extend(["", "*Remediation:*"])
        lines.extend(f"- {item}" for item in recommendations)

    cx_links = unique_values(finding.cx_url for finding in group.findings if finding.cx_url)
    if cx_links:
        lines.extend(["", "*Checkmarx links:*"])
        lines.extend(f"- {item}" for item in cx_links)

    return "\n".join(lines)


def build_update_comment(group: FindingGroup) -> str:
    scan_ids = unique_values(finding.scan_id for finding in group.findings if finding.scan_id)
    scan_text = ", ".join(scan_ids) if scan_ids else "unknown scan"
    return (
        f"Checkmarx finding group still present in latest sync. "
        f"Occurrences: {len(group.findings)}. Scan IDs: {scan_text}."
    )


def component_for(finding: CxFinding, config: SyncConfig) -> str:
    if config.group_by_component:
        return finding.component or infer_component_from_path(finding.file_path)
    return "all-components"


def infer_component_from_path(file_path: Optional[str]) -> str:
    if not file_path:
        return "unknown-component"

    normalized = file_path.replace("\\", "/").strip("/")
    if not normalized:
        return "unknown-component"

    return normalized.split("/")[0]


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.strip().lower(), SEVERITY_ORDER["medium"])


def max_severity(severities: Iterable[str]) -> str:
    return max(severities, key=severity_rank)


def stable_hash(parts: Iterable[str]) -> str:
    canonical = "|".join(part.strip().lower() for part in parts)
    return sha256(canonical.encode("utf-8")).hexdigest()[:24]


def first_present(raw: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return value
    return default


def optional_str(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    return str(value)


def optional_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_label(value: str) -> str:
    return value.lower().replace(" ", "-").replace("_", "-")


def unique_values(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
