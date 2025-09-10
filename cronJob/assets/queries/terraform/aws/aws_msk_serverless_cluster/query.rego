package main

__rego_metadoc__ := {
  "id": "KICS-AWS-1001",
  "title": "MSK Serverless cluster should not enable bootstrap_brokers_sasl_iam without IAM policy restrictions",
  "severity": "MEDIUM",
  "description": "Enabling bootstrap_brokers_sasl_iam without explicit IAM policy restrictions may allow unintended principals to retrieve bootstrap brokers.",
  "provider": "aws",
  "resource": "aws_msk_serverless_cluster"
}

deny[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  after := resource.change.after
  after.bootstrap_brokers_sasl_iam == true
  # No IAM policy restrictions block access
  not after.client_authentication.sasl.iam.policy
  issue := {
    "msg": sprintf("Resource '%s' enables bootstrap_brokers_sasl_iam without an IAM policy restriction", [resource.address]),
    "resource": resource.address
  }
}