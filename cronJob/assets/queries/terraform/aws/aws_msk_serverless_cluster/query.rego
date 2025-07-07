package main

__rego_metadata__ := {
  "id": "MSK001",
  "title": "AWS MSK Serverless cluster SASL_IAM authentication enabled",
  "description": "Detects when bootstrap_brokers_sasl_iam is enabled on MSK Serverless clusters, which may expose broker endpoints requiring broad IAM permissions.",
  "severity": "MEDIUM",
  "provider": "aws",
  "service": "msk",
  "platform": "terraform"
}

deny[violation] {
  rc := input.resource_changes[_]
  rc.type == "aws_msk_serverless_cluster"
  after := rc.change.after
  after.bootstrap_brokers_sasl_iam == true
  violation := {
    "message": sprintf("Resource %s has bootstrap_brokers_sasl_iam enabled, ensure IAM policies are scoped tightly.", [rc.address]),
    "resource": rc.address
  }
}