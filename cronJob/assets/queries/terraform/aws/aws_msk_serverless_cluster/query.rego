package main

__rego_meta__ := {
  "id": "KICS-AWS-INFO-001",
  "version": "1.0.0",
  "type": "terraform",
  "supported_resources": ["aws_msk_serverless_cluster"],
  "categories": ["security"],
  "severity": "HIGH",
  "description": "Detects AWS MSK Serverless clusters enabling bootstrap_brokers_sasl_iam, which can expose endpoints to IAM-based SASL authentication without proper restrictions."
}

deny[resource] {
  resource := input.resource[_]
  resource.Type == "aws_msk_serverless_cluster"
  resource.Values.bootstrap_brokers_sasl_iam == true
}
