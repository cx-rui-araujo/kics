package terraform.rules.aws

import data.tfplan as tfplan

__rego_metadata__ := {
  "id": "CUSTOM_AWS_001",
  "title": "AWS MSK Serverless cluster SASL IAM enabled without restrictive policy",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "confidence": "MEDIUM"
}

violation[violation] {
  rc := tfplan.resource_changes[_]
  rc.type == "aws_msk_serverless_cluster"
  rc.change.after.bootstrap_brokers_sasl_iam == true
  violation := {
    "resource": rc.address,
    "message": "MSK Serverless cluster has bootstrap_brokers_sasl_iam enabled; ensure restrictive IAM policy for GetBootstrapBrokers is in place."
  }
}