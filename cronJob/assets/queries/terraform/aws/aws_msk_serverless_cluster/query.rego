package kics

violation[{
  "msg": msg,
  "resource": resource.address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam == true
  msg := "Enabling bootstrap_brokers_sasl_iam may grant excessive kafka:GetBootstrapBrokers permissions. Restrict IAM policy to specific MSK cluster ARNs."
}