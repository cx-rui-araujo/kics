package terraform.aws_msk_serverless_cluster

# Prevent enabling SASL IAM without restricted IAM policies
violation[resource] {
  rc := input.resource_changes[_]
  rc.type == "aws_msk_serverless_cluster"
  after := rc.change.after
  after.bootstrap_brokers_sasl_iam == true
  resource := rc.address
}