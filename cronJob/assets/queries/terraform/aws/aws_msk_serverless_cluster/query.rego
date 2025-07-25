package kics

violation[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  after := resource.change.after
  after.bootstrap_brokers_sasl_iam == true
  message := sprintf("aws_msk_serverless_cluster '%s' has bootstrap_brokers_sasl_iam enabled, allowing any IAM principal with kafka:GetBootstrapBrokers to retrieve broker endpoints and potentially gain unauthorized access.", [resource.address])
}