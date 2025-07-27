package main

__rego_metadata__ := {
  "id": "AWS_KICS_001",
  "title": "MSK Serverless cluster SASL IAM authentication enabled",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

deny[msg] {
  input.resource_type == "aws_msk_serverless_cluster"
  input.values.bootstrap_brokers_sasl_iam == true
  msg = sprintf("Resource '%s' enables SASL IAM authentication, potentially exposing broker endpoints or allowing unauthorized access.", [input.resource_name])
}