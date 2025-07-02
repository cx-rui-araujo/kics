package check_aws_msk_serverless_cluster

default severity = "MEDIUM"

description = "Ensure aws_msk_serverless_cluster does not expose bootstrap brokers via SASL/IAM without proper network restrictions"

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam == true
}