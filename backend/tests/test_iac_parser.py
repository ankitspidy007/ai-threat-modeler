import os
import sys
import pytest
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.append(str(backend_dir))

from app.engine.iac_parser import IaCParser
from app.engine.analyzer import ThreatAnalyzer

def test_docker_compose_parsing():
    compose_yaml = """
version: '3.8'
services:
  web_frontend:
    image: nginx:latest
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - api_server
      
  api_server:
    image: myapp/api:v1
    environment:
      - DATABASE_URL=postgres://user:pass@db_postgres:5432/mydb
      - REDIS_URL=redis://cache_redis:6379/0
      
  db_postgres:
    image: postgres:14
    environment:
      - POSTGRES_PASSWORD=supersecret
      
  cache_redis:
    image: redis:alpine
"""
    parser = IaCParser()
    architecture = parser.parse(compose_yaml, format_hint='docker-compose')
    
    # 4 services = 4 components
    assert len(architecture.components) == 4
    
    # Check types
    web = next(c for c in architecture.components if c.id == 'web_frontend')
    api = next(c for c in architecture.components if c.id == 'api_server')
    db = next(c for c in architecture.components if c.id == 'db_postgres')
    cache = next(c for c in architecture.components if c.id == 'cache_redis')
    
    assert web.type == 'WebClient'
    assert api.type == 'API'
    assert db.type == 'Database'
    
    # Check properties
    assert web.properties.get('public_access') is True
    assert db.properties.get('secrets_in_env') is True
    
    
    # Check flows
    flows = architecture.flows
    web_targets = [f.target_id for f in flows if f.source_id == 'web_frontend']
    api_targets = [f.target_id for f in flows if f.source_id == 'api_server']

    assert 'api_server' in web_targets  # From depends_on
    assert 'db_postgres' in api_targets # From env var URL matching
    assert 'cache_redis' in api_targets # From env var URL matching

def test_kubernetes_parsing():
    k8s_yaml = """
apiVersion: v1
kind: Service
metadata:
  name: my-api-service
spec:
  type: LoadBalancer
  selector:
    app: my-api
  ports:
    - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-api-deployment
spec:
  template:
    metadata:
      labels:
        app: my-api
    spec:
      containers:
      - name: api
        image: python-fastapi:latest
        securityContext:
          privileged: true
"""
    parser = IaCParser()
    architecture = parser.parse(k8s_yaml, format_hint='kubernetes')
    
    # 1 deployment = 1 component (Service is just metadata context)
    assert len(architecture.components) == 1
    
    api = architecture.components[0]
    assert api.id == 'my-api-deployment'
    assert api.type == 'API'
    
    # Linked via service selector implicitly
    assert api.properties.get('containerized') is True


def test_terraform_security_findings_include_critical_aws_misconfigurations():
    terraform = '''
resource "aws_s3_bucket" "uploads" {
  bucket = "customer-uploads"
  acl    = "public-read"
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_lambda_permission" "public" {
  action        = "lambda:InvokeFunction"
  function_name = "processor"
  principal     = "*"
}

resource "aws_security_group" "database" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "primary" {
  publicly_accessible = true
  storage_encrypted   = false
}
'''
    architecture = IaCParser().parse(terraform, format_hint='terraform')
    findings = architecture.metadata['iac_findings']
    rule_ids = {finding['rule_id'] for finding in findings}

    assert 'IAC-AWS-S3-PUBLIC-ACL' in rule_ids
    assert 'IAC-AWS-IAM-ADMIN' in rule_ids
    assert 'IAC-AWS-LAMBDA-PUBLIC-INVOKE' in rule_ids
    assert 'IAC-AWS-EC2-OPEN-SECURITY-GROUP' in rule_ids
    assert 'IAC-AWS-RDS-PUBLIC' in rule_ids

    result = ThreatAnalyzer().analyze(architecture, 'Terraform Critical Findings')
    assert any(threat.id.startswith('IAC-AWS-IAM-ADMIN') and threat.tier == 'Confirmed' for threat in result.threats)


def test_cloudformation_and_kubernetes_critical_findings_are_preserved():
    cloudformation = '''
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      StorageEncrypted: false
  PublicFunction:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: processor
      Principal: '*'
'''
    cfn_architecture = IaCParser().parse(cloudformation, format_hint='cloudformation')
    cfn_rules = {finding['rule_id'] for finding in cfn_architecture.metadata['iac_findings']}
    assert {'IAC-AWS-RDS-PUBLIC', 'IAC-AWS-RDS-NO-ENCRYPTION', 'IAC-AWS-LAMBDA-PUBLIC-INVOKE'} <= cfn_rules

    kubernetes = '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: processor
spec:
  template:
    metadata:
      labels:
        app: processor
    spec:
      hostNetwork: true
      containers:
        - name: processor
          image: example/processor:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
'''
    k8s_architecture = IaCParser().parse(kubernetes, format_hint='kubernetes')
    k8s_rules = {finding['rule_id'] for finding in k8s_architecture.metadata['iac_findings']}
    assert {'IAC-K8S-HOST-NAMESPACE', 'IAC-K8S-PRIVILEGED-CONTAINER', 'IAC-K8S-PRIV-ESCALATION'} <= k8s_rules

if __name__ == '__main__':
    print("Running IaC parsing tests...")
    test_docker_compose_parsing()
    print("Docker Compose parsing: PASSED")
    test_kubernetes_parsing()
    print("Kubernetes parsing: PASSED")
    print("All tests passed.")
