package terraform.msksasl

__rego_metadata__ := {
  "id": "KICS-AWS-EXAMPLE-001",
  "title": "AWS MSK Serverless cluster SASL/IAM bootstrap brokers enabled",
  "description": "Detect when bootstrap_brokers_sasl_iam is enabled to ensure proper IAM policies are applied",
  "severity": "MEDIUM",
  "category": "Security",
  "cwe": "CWE-916"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam == true
}