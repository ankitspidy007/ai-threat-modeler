"""Deterministic, resource-level IaC security checks.

This module deliberately keeps parsing conservative: findings require an explicit
insecure value or a public/excessive permission.  It complements architecture
threat modeling with evidence-backed configuration findings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


class IaCSecurityAnalyzer:
    """Find high-signal security issues in common AWS and container IaC."""

    _terraform_resource = re.compile(
        r'^\s*resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{', re.MULTILINE
    )

    def analyze(self, content: str, format_hint: str = "auto", documents: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        format_name = (format_hint or "auto").lower()
        findings: List[Dict[str, Any]] = []

        if format_name == "terraform" or self._terraform_resource.search(content):
            findings.extend(self._analyze_terraform(content))

        if documents is None and format_name != "terraform":
            try:
                documents = [doc for doc in yaml.safe_load_all(content) if isinstance(doc, dict)]
            except yaml.YAMLError:
                documents = []

        for document in documents or []:
            if "Resources" in document or "AWSTemplateFormatVersion" in document:
                findings.extend(self._analyze_cloudformation(document, content))
            if "apiVersion" in document and "kind" in document:
                findings.extend(self._analyze_kubernetes(document, content))
            if "services" in document:
                findings.extend(self._analyze_compose(document, content))

        return self._deduplicate(findings)

    def _analyze_terraform(self, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        resources = list(self._terraform_blocks(content))
        resource_types = {resource_type for resource_type, _, _, _ in resources}

        for resource_type, name, block, line in resources:
            resource_id = f"{resource_type}.{name}"
            lowered = block.lower()

            if resource_type == "aws_s3_bucket":
                if re.search(r'\bacl\s*=\s*"public-(?:read|read-write|write)"', block, re.I):
                    findings.append(self._finding("IAC-AWS-S3-PUBLIC-ACL", resource_id, line, "Critical", "Public S3 bucket ACL", "The bucket ACL explicitly grants public access, allowing anonymous data exposure or modification.", "Disable public ACLs, enable all S3 public-access blocks, and grant access through narrowly scoped IAM policies.", "Information Disclosure", "CWE-200"))
                if not any(item.startswith("aws_s3_bucket_public_access_block") for item in resource_types):
                    findings.append(self._finding("IAC-AWS-S3-MISSING-PAB", resource_id, line, "High", "S3 bucket lacks a public-access block", "No aws_s3_bucket_public_access_block resource is present, so an ACL or policy can later expose the bucket publicly.", "Create a public-access block for this bucket with all four block settings enabled.", "Information Disclosure", "CWE-284"))
                if "server_side_encryption_configuration" not in lowered:
                    findings.append(self._finding("IAC-AWS-S3-NO-ENCRYPTION", resource_id, line, "High", "S3 bucket encryption is not configured", "The bucket resource has no server-side encryption configuration.", "Configure default SSE-KMS or SSE-S3 encryption and enforce encryption in the bucket policy.", "Information Disclosure", "CWE-311"))
                if "versioning" not in lowered:
                    findings.append(self._finding("IAC-AWS-S3-NO-VERSIONING", resource_id, line, "Medium", "S3 bucket versioning is not configured", "Object versioning is absent, increasing the impact of accidental or malicious object deletion.", "Enable S3 versioning and use lifecycle controls appropriate for the data retention policy.", "Tampering", "CWE-693"))

            if resource_type == "aws_s3_bucket_public_access_block" and re.search(r'\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false', block, re.I):
                findings.append(self._finding("IAC-AWS-S3-PAB-DISABLED", resource_id, line, "High", "S3 public-access protections are disabled", "At least one S3 public-access block setting is explicitly disabled.", "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.", "Information Disclosure", "CWE-284"))

            if resource_type == "aws_s3_bucket_policy" and self._public_principal(block):
                findings.append(self._finding("IAC-AWS-S3-PUBLIC-POLICY", resource_id, line, "Critical", "S3 bucket policy permits public access", "The bucket policy contains a wildcard principal, allowing anonymous access when actions and conditions permit it.", "Restrict the Principal and resources to required IAM roles; add explicit secure-transport and organization conditions.", "Information Disclosure", "CWE-200"))
            elif resource_type in {"aws_iam_policy", "aws_iam_role", "aws_iam_user_policy", "aws_iam_role_policy", "aws_iam_group_policy"}:
                findings.extend(self._analyze_policy_text(block, resource_id, line))

            if resource_type == "aws_iam_role" and "AdministratorAccess" in block:
                findings.append(self._finding("IAC-AWS-IAM-MANAGED-ADMIN", resource_id, line, "Critical", "IAM role attaches AdministratorAccess", "The role attaches the AWS managed AdministratorAccess policy.", "Replace AdministratorAccess with a workload-specific policy limited to required actions and resources.", "Elevation of Privilege", "CWE-250"))

            if resource_type == "aws_kms_key":
                if self._public_principal(block):
                    findings.append(self._finding("IAC-AWS-KMS-PUBLIC-KEY", resource_id, line, "Critical", "KMS key policy permits a public principal", "The KMS key policy contains a wildcard principal, enabling unauthorized use or administration of cryptographic keys.", "Restrict key-policy principals to required roles and accounts; never use a wildcard principal.", "Elevation of Privilege", "CWE-284"))
                if re.search(r'\benable_key_rotation\s*=\s*false', block, re.I):
                    findings.append(self._finding("IAC-AWS-KMS-ROTATION-DISABLED", resource_id, line, "High", "KMS key rotation is disabled", "Automatic rotation is explicitly disabled for a customer-managed KMS key.", "Enable automatic key rotation and define a rotation and revocation process.", "Information Disclosure", "CWE-320"))
                if re.search(r'\bdeletion_window_in_days\s*=\s*[0-6]\b', block, re.I):
                    findings.append(self._finding("IAC-AWS-KMS-SHORT-DELETION", resource_id, line, "Medium", "KMS key deletion window is too short", "The KMS key can be permanently deleted with less than the recommended seven-day recovery window.", "Use a deletion window of at least seven days and protect critical keys with organizational controls.", "Denial of Service", "CWE-693"))

            if resource_type == "aws_lambda_permission" and re.search(r'\bprincipal\s*=\s*"\*"', block, re.I):
                findings.append(self._finding("IAC-AWS-LAMBDA-PUBLIC-INVOKE", resource_id, line, "Critical", "Lambda permission allows public invocation", "The Lambda permission grants invocation to every AWS principal.", "Limit the principal and source ARN/account to the exact trusted event source or API Gateway.", "Spoofing", "CWE-284"))

            if resource_type == "aws_lambda_function":
                if self._contains_literal_secret(block):
                    findings.append(self._finding("IAC-AWS-LAMBDA-HARDCODED-SECRET", resource_id, line, "High", "Lambda environment contains a likely hard-coded secret", "A secret-like environment variable is assigned a literal value in the function configuration.", "Store the secret in AWS Secrets Manager or SSM Parameter Store and grant the execution role read access only to that secret.", "Information Disclosure", "CWE-798"))
                if re.search(r'\btimeout\s*=\s*(?:[3-9]\d{2}|[1-9]\d{3,})', block, re.I):
                    findings.append(self._finding("IAC-AWS-LAMBDA-LONG-TIMEOUT", resource_id, line, "Medium", "Lambda timeout is excessively long", "The configured timeout is at least five minutes, increasing the blast radius of abusive or stuck invocations.", "Set the shortest practical timeout and configure reserved concurrency and alarms.", "Denial of Service", "CWE-400"))

            if resource_type == "aws_lambda_function_url" and re.search(r'\bauthorization_type\s*=\s*"NONE"', block, re.I):
                findings.append(self._finding("IAC-AWS-LAMBDA-URL-PUBLIC", resource_id, line, "High", "Lambda function URL has no authorization", "The Lambda function URL explicitly uses authorization_type = NONE.", "Use AWS_IAM authorization or place the function behind an authenticated API Gateway.", "Spoofing", "CWE-306"))

            if resource_type in {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}:
                findings.extend(self._analyze_security_group(block, resource_id, line))

            if resource_type == "aws_instance":
                if re.search(r'\bassociate_public_ip_address\s*=\s*true', block, re.I):
                    findings.append(self._finding("IAC-AWS-EC2-PUBLIC-IP", resource_id, line, "High", "EC2 instance receives a public IP address", "The instance is explicitly configured with a public IP, increasing its internet exposure.", "Place workloads in private subnets and expose only controlled load balancers or bastions.", "Information Disclosure", "CWE-668"))
                if re.search(r'\bhttp_tokens\s*=\s*"optional"', block, re.I):
                    findings.append(self._finding("IAC-AWS-EC2-IMDSV1", resource_id, line, "High", "EC2 instance permits IMDSv1", "Instance metadata tokens are optional, allowing tokenless metadata requests that are vulnerable to SSRF abuse.", "Set metadata_options.http_tokens to required and restrict metadata hop limits.", "Information Disclosure", "CWE-918"))
                if re.search(r'\bencrypted\s*=\s*false', block, re.I):
                    findings.append(self._finding("IAC-AWS-EC2-UNENCRYPTED-EBS", resource_id, line, "High", "EC2 block storage encryption is disabled", "An EBS block device is explicitly configured without encryption.", "Enable EBS encryption using an approved KMS key for every root and data volume.", "Information Disclosure", "CWE-311"))

            if resource_type == "aws_db_instance":
                if re.search(r'\bpublicly_accessible\s*=\s*true', block, re.I):
                    findings.append(self._finding("IAC-AWS-RDS-PUBLIC", resource_id, line, "Critical", "RDS instance is publicly accessible", "The database is explicitly reachable from outside its VPC when security-group rules allow it.", "Set publicly_accessible to false, use private subnets, and restrict database security groups to application sources.", "Information Disclosure", "CWE-668"))
                if re.search(r'\bstorage_encrypted\s*=\s*false', block, re.I):
                    findings.append(self._finding("IAC-AWS-RDS-NO-ENCRYPTION", resource_id, line, "High", "RDS storage encryption is disabled", "The database storage is explicitly configured without encryption at rest.", "Enable storage_encrypted and use a managed KMS key with a restricted key policy.", "Information Disclosure", "CWE-311"))
                if re.search(r'\bbackup_retention_period\s*=\s*0', block, re.I):
                    findings.append(self._finding("IAC-AWS-RDS-NO-BACKUP", resource_id, line, "High", "RDS automated backups are disabled", "The backup retention period is set to zero, preventing point-in-time recovery.", "Set a non-zero backup-retention period and test recovery procedures.", "Denial of Service", "CWE-693"))

            if resource_type == "aws_api_gateway_method" and re.search(r'\bauthorization\s*=\s*"NONE"', block, re.I):
                findings.append(self._finding("IAC-AWS-APIGW-NO-AUTH", resource_id, line, "High", "API Gateway method has no authorization", "The method explicitly uses authorization = NONE.", "Require IAM, Cognito, JWT, or a Lambda authorizer for non-public operations.", "Spoofing", "CWE-306"))

            if resource_type == "aws_eks_cluster" and re.search(r'\bendpoint_public_access\s*=\s*true', block, re.I):
                findings.append(self._finding("IAC-AWS-EKS-PUBLIC-ENDPOINT", resource_id, line, "Critical", "EKS control-plane endpoint is public", "The EKS cluster explicitly enables a public Kubernetes API endpoint.", "Disable public endpoint access or tightly restrict public_access_cidrs and enforce strong IAM/RBAC.", "Elevation of Privilege", "CWE-284"))

        return findings

    def _analyze_cloudformation(self, document: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for logical_id, resource in (document.get("Resources") or {}).items():
            if not isinstance(resource, dict):
                continue
            resource_type = resource.get("Type", "")
            props = resource.get("Properties") or {}
            line = self._line_for(content, str(logical_id))
            if resource_type == "AWS::S3::Bucket":
                access_block = props.get("PublicAccessBlockConfiguration") or {}
                if any(access_block.get(key) is False for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                    findings.append(self._finding("IAC-AWS-S3-PAB-DISABLED", logical_id, line, "High", "S3 public-access protections are disabled", "The CloudFormation bucket disables at least one public-access-block setting.", "Enable all S3 public-access-block settings and use least-privilege bucket policies.", "Information Disclosure", "CWE-284"))
                if props.get("AccessControl") in {"PublicRead", "PublicReadWrite", "AuthenticatedRead"}:
                    findings.append(self._finding("IAC-AWS-S3-PUBLIC-ACL", logical_id, line, "Critical", "Public S3 bucket ACL", "The bucket AccessControl property grants broad access.", "Remove the public ACL and grant access using restricted IAM policies.", "Information Disclosure", "CWE-200"))
                if not props.get("BucketEncryption"):
                    findings.append(self._finding("IAC-AWS-S3-NO-ENCRYPTION", logical_id, line, "High", "S3 bucket encryption is not configured", "The bucket has no BucketEncryption configuration.", "Configure default SSE-KMS or SSE-S3 encryption.", "Information Disclosure", "CWE-311"))
            elif resource_type == "AWS::RDS::DBInstance":
                if props.get("PubliclyAccessible") is True:
                    findings.append(self._finding("IAC-AWS-RDS-PUBLIC", logical_id, line, "Critical", "RDS instance is publicly accessible", "PubliclyAccessible is explicitly true.", "Set PubliclyAccessible to false and use private subnets and restricted security groups.", "Information Disclosure", "CWE-668"))
                if props.get("StorageEncrypted") is False:
                    findings.append(self._finding("IAC-AWS-RDS-NO-ENCRYPTION", logical_id, line, "High", "RDS storage encryption is disabled", "StorageEncrypted is explicitly false.", "Enable encryption at rest with KMS.", "Information Disclosure", "CWE-311"))
            elif resource_type == "AWS::Lambda::Permission" and props.get("Principal") == "*":
                findings.append(self._finding("IAC-AWS-LAMBDA-PUBLIC-INVOKE", logical_id, line, "Critical", "Lambda permission allows public invocation", "The Lambda permission principal is a wildcard.", "Restrict the principal and SourceArn to the trusted invoking service.", "Spoofing", "CWE-284"))
            elif resource_type == "AWS::EC2::SecurityGroup":
                for rule in props.get("SecurityGroupIngress") or []:
                    if isinstance(rule, dict) and rule.get("CidrIp") in {"0.0.0.0/0", "::/0"}:
                        port = rule.get("FromPort")
                        severity = "Critical" if port in {22, 3389, 3306, 5432, 6379, 27017} else "High"
                        findings.append(self._finding("IAC-AWS-EC2-OPEN-SECURITY-GROUP", logical_id, line, severity, "Security group exposes a port to the internet", f"Ingress permits {rule.get('CidrIp')} on port {port}.", "Restrict the source CIDR to trusted ranges or use a security-group reference.", "Elevation of Privilege", "CWE-284"))
            elif resource_type == "AWS::IAM::ManagedPolicy":
                findings.extend(self._analyze_policy_text(str(props.get("PolicyDocument", "")), logical_id, line))
            elif resource_type == "AWS::KMS::Key" and self._public_principal(str(props.get("KeyPolicy", ""))):
                findings.append(self._finding("IAC-AWS-KMS-PUBLIC-KEY", logical_id, line, "Critical", "KMS key policy permits a public principal", "The KMS KeyPolicy contains a wildcard principal.", "Restrict principals to the minimum required IAM roles and accounts.", "Elevation of Privilege", "CWE-284"))
        return findings

    def _analyze_kubernetes(self, document: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        kind = document.get("kind", "")
        name = (document.get("metadata") or {}).get("name", kind)
        line = self._line_for(content, str(name))
        spec = document.get("spec") or {}
        pod_spec = spec.get("template", {}).get("spec", spec) if kind != "Pod" else spec

        if kind == "Service" and spec.get("type") in {"LoadBalancer", "NodePort"}:
            findings.append(self._finding("IAC-K8S-PUBLIC-SERVICE", name, line, "High", "Kubernetes Service exposes workloads externally", f"Service type {spec.get('type')} exposes the workload outside the cluster.", "Use ClusterIP by default and expose only authenticated ingress endpoints with network policies.", "Information Disclosure", "CWE-668"))
        if kind in {"Role", "ClusterRole"}:
            for rule in document.get("rules") or []:
                if "*" in (rule.get("verbs") or []) and "*" in (rule.get("resources") or []):
                    findings.append(self._finding("IAC-K8S-RBAC-WILDCARD", name, line, "Critical", "Kubernetes RBAC grants wildcard privileges", "The role permits all verbs on all resources.", "Grant only required verbs and resources; avoid cluster-admin for workloads.", "Elevation of Privilege", "CWE-250"))
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"}:
            if pod_spec.get("hostNetwork") is True or pod_spec.get("hostPID") is True:
                findings.append(self._finding("IAC-K8S-HOST-NAMESPACE", name, line, "High", "Pod shares a host namespace", "hostNetwork or hostPID is enabled, reducing container isolation.", "Disable host namespace sharing unless a documented platform exception requires it.", "Elevation of Privilege", "CWE-250"))
            for container in pod_spec.get("containers") or []:
                security = container.get("securityContext") or {}
                image = str(container.get("image", ""))
                if security.get("privileged") is True:
                    findings.append(self._finding("IAC-K8S-PRIVILEGED-CONTAINER", name, line, "Critical", "Kubernetes container runs privileged", "A container security context explicitly enables privileged mode.", "Set privileged to false and remove unnecessary Linux capabilities.", "Elevation of Privilege", "CWE-250"))
                if security.get("allowPrivilegeEscalation") is True:
                    findings.append(self._finding("IAC-K8S-PRIV-ESCALATION", name, line, "High", "Kubernetes container allows privilege escalation", "allowPrivilegeEscalation is explicitly true.", "Set allowPrivilegeEscalation to false and enforce the restricted Pod Security Standard.", "Elevation of Privilege", "CWE-269"))
                if image.endswith(":latest") or ":" not in image:
                    findings.append(self._finding("IAC-K8S-UNPINNED-IMAGE", name, line, "Medium", "Container image is not pinned", "The image uses latest or has no immutable tag.", "Pin images by immutable digest and enforce image provenance controls.", "Tampering", "CWE-829"))
        return findings

    def _analyze_compose(self, document: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for name, service in (document.get("services") or {}).items():
            if not isinstance(service, dict):
                continue
            line = self._line_for(content, str(name))
            if service.get("privileged") is True:
                findings.append(self._finding("IAC-COMPOSE-PRIVILEGED", name, line, "Critical", "Compose service runs privileged", "The service explicitly enables privileged mode.", "Remove privileged mode and add only the specific capabilities required.", "Elevation of Privilege", "CWE-250"))
            if service.get("network_mode") == "host":
                findings.append(self._finding("IAC-COMPOSE-HOST-NETWORK", name, line, "High", "Compose service uses the host network", "network_mode: host removes network isolation from the container.", "Use a dedicated Docker network and expose only required ports.", "Elevation of Privilege", "CWE-668"))
            image = str(service.get("image", ""))
            if image.endswith(":latest") or (image and ":" not in image):
                findings.append(self._finding("IAC-COMPOSE-UNPINNED-IMAGE", name, line, "Medium", "Container image is not pinned", "The service image uses latest or has no immutable tag.", "Pin images by immutable digest and enforce image provenance controls.", "Tampering", "CWE-829"))
        return findings

    def _analyze_policy_text(self, text: str, resource_id: str, line: int) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        action_wildcard = bool(re.search(r'\b(?:Action|actions?)\b\s*[=:]\s*(?:\[\s*)?["\']?\*', text, re.I))
        resource_wildcard = bool(re.search(r'\b(?:Resource|resources?)\b\s*[=:]\s*(?:\[\s*)?["\']?\*', text, re.I))
        if action_wildcard and resource_wildcard:
            findings.append(self._finding("IAC-AWS-IAM-ADMIN", resource_id, line, "Critical", "IAM policy grants administrator-equivalent access", "The policy permits every action on every resource.", "Replace wildcard permissions with the minimum required actions, resources, and conditions.", "Elevation of Privilege", "CWE-250"))
        elif action_wildcard:
            findings.append(self._finding("IAC-AWS-IAM-WILDCARD-ACTION", resource_id, line, "High", "IAM policy uses a wildcard action", "The policy permits all actions, exceeding least-privilege boundaries.", "Enumerate only required actions and constrain access with resources and conditions.", "Elevation of Privilege", "CWE-250"))
        if self._public_principal(text):
            findings.append(self._finding("IAC-AWS-IAM-PUBLIC-TRUST", resource_id, line, "Critical", "IAM policy trusts every principal", "The policy or trust relationship contains a wildcard principal.", "Restrict Principal to known accounts, roles, or services and add external-ID conditions for third parties.", "Spoofing", "CWE-284"))
        if re.search(r'\biam:PassRole\b.*["\']?\*|["\']?\*.*\biam:PassRole\b', text, re.I | re.S):
            findings.append(self._finding("IAC-AWS-IAM-PASSROLE", resource_id, line, "Critical", "IAM policy can pass arbitrary roles", "iam:PassRole is combined with an unrestricted resource.", "Restrict iam:PassRole to named roles and add iam:PassedToService conditions.", "Elevation of Privilege", "CWE-269"))
        return findings

    def _analyze_security_group(self, block: str, resource_id: str, line: int) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not re.search(r'(?:cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*(?:"0\.0\.0\.0/0"|"::/0")|\bcidr_ipv[46]\s*=\s*"(?:0\.0\.0\.0/0|::/0)"', block, re.I | re.S):
            return findings
        port_match = re.search(r'\bfrom_port\s*=\s*(\d+)', block, re.I)
        port = int(port_match.group(1)) if port_match else None
        severity = "Critical" if port in {22, 3389, 3306, 5432, 6379, 27017, 9200} else "High"
        findings.append(self._finding("IAC-AWS-EC2-OPEN-SECURITY-GROUP", resource_id, line, severity, "Security group exposes a port to the internet", f"Ingress permits 0.0.0.0/0 or ::/0 on port {port if port is not None else 'an unspecified port'}.", "Restrict ingress to trusted CIDRs or security-group references, especially for administration and data ports.", "Elevation of Privilege", "CWE-284"))
        return findings

    def _terraform_blocks(self, content: str) -> Iterable[Tuple[str, str, str, int]]:
        for match in self._terraform_resource.finditer(content):
            start = match.end()
            depth = 1
            index = start
            quote = None
            escaped = False
            while index < len(content) and depth:
                char = content[index]
                if quote:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == quote:
                        quote = None
                elif char in {"\"", "'"}:
                    quote = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                index += 1
            yield match.group("type"), match.group("name"), content[match.start():index], content.count("\n", 0, match.start()) + 1

    @staticmethod
    def _public_principal(text: str) -> bool:
        return bool(re.search(r'\bPrincipal\b\s*[=:]\s*(?:\{[^}]*["\']?AWS["\']?\s*[=:]\s*)?["\']?\*', text, re.I | re.S))

    @staticmethod
    def _contains_literal_secret(text: str) -> bool:
        return bool(re.search(r'\b(?:password|secret|token|api[_-]?key)\w*\s*=\s*["\'][^"\']{8,}["\']', text, re.I))

    @staticmethod
    def _line_for(content: str, token: str) -> int:
        location = content.find(token)
        return content.count("\n", 0, location) + 1 if location >= 0 else 1

    @staticmethod
    def _finding(rule_id: str, resource_id: str, line: int, severity: str, title: str, description: str, mitigation: str, category: str, cwe: str) -> Dict[str, Any]:
        return {
            "id": f"{rule_id}:{resource_id}",
            "rule_id": rule_id,
            "resource_id": resource_id,
            "line": line,
            "severity": severity,
            "title": title,
            "description": description,
            "mitigation": mitigation,
            "category": category,
            "cwe": [cwe],
            "evidence": [f"IaC resource {resource_id}, line {line}: {description}"],
        }

    @staticmethod
    def _deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            unique[finding["id"]] = finding
        return list(unique.values())
