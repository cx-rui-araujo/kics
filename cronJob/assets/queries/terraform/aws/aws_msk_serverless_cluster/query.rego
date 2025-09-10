package kics

deny[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam
  not resource.change.after.client_authentication.sasl.iam
  message := sprintf("Resource '%v' has bootstrap_brokers_sasl_iam enabled without enforcing SASL IAM authentication", [resource.address])
}