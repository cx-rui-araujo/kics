package main

__rego_metadata__ := {
  "id": "KICS_AWS_MSK_001",
  "title": "Ensure MSK Serverless Cluster SASL IAM bootstrap brokers is disabled",
  "severity": "LOW",
  "type": "Misconfiguration",
  "description": "Enabling bootstrap_brokers_sasl_iam may leak broker endpoints in the Terraform state file, exposing internal endpoints if the state is shared or committed to version control."
}

violation[resource] {
  resource := tfconfig.resource.aws_msk_serverless_cluster[_]
  resource.values.bootstrap_brokers_sasl_iam == true
}