package terraform.aws.msk

# Deny if aws_msk_serverless_cluster enables bootstrap_brokers_sasl_iam
deny[msg] {
  resource := tfconfig.resources["aws_msk_serverless_cluster"][name]
  resource.values.bootstrap_brokers_sasl_iam == true
  msg := sprintf("Resource '%s' enables bootstrap_brokers_sasl_iam which may expose IAM credentials to clients", [name])
}