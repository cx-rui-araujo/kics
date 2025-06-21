package main

__rego_metadata__ = {"id": "CUSTOM_AWS_001", "title": "AWS MSK Serverless cluster uses SASL IAM endpoint", "severity": "HIGH", "description": "Detects use of bootstrap_brokers_sasl_iam on MSK Serverless clusters without least‐privilege IAM policies."}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam == true
  resource = {"address": resource.address}
}