package kics

__rego_metadata__ := {
  "id": "AWS-MSK-001",
  "title": "AWS MSK Serverless cluster SASL IAM authentication enabled",
  "severity": "MEDIUM",
  "type": "Misconfiguration",
  "reference_id": "MSK-SASL-IAM"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam == true
}