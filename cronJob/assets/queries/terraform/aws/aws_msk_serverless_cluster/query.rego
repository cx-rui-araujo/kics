package terraform.aws_msk

import input as tfplan

violation[rule] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  # If bootstrap_brokers_sasl_iam is not enabled, cluster uses insecure plaintext bootstrap
  not resource.change.after.bootstrap_brokers_sasl_iam
  rule := {
    "resource": resource.address,
    "message": "AWS MSK Serverless cluster should have bootstrap_brokers_sasl_iam enabled for secure IAM SASL authentication",
    "severity": "HIGH"
  }
}