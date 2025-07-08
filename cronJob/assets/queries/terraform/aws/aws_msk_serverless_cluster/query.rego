package terraform.tfplan

deny[msg] {
  resource := tfplan.resource_changes.aws_msk_serverless_cluster[_]
  resource.change.after.bootstrap_brokers_sasl_iam == true
  msg := sprintf("Resource %v enables bootstrap_brokers_sasl_iam without proper IAM policy restrictions", [resource.address])
}