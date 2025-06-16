package main

__rego_metadata__ = {"id": "KICS-EXAMPLE-1","version": "1.0.0","title": "MSK Serverless cluster with SASL IAM enabled","description": "Detects aws_msk_serverless_cluster resources with bootstrap_brokers_sasl_iam enabled which may expose bootstrap brokers endpoint via IAM.","severity": "MEDIUM","category": "Security Best Practices","type": "VULNERABILITY","input_type": "Terraform"}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  after := resource.change.after
  after.bootstrap_brokers_sasl_iam == true
  msg = sprintf("Resource '%v' enables bootstrap_brokers_sasl_iam which may expose bootstrap brokers endpoint to unauthorized IAM principals.", [resource.address])
}