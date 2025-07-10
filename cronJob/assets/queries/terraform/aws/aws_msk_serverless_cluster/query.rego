package terraform.aws.security

den y[res] {
  res := input.resource_changes[_]
  res.type == "aws_msk_serverless_cluster"
  res.change.after.bootstrap_brokers_sasl_iam == true
}