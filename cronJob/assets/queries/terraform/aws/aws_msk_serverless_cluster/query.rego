package terraform.aws.MskServerlessCluster

violation[resource] {
  resource := input.resource.aws_msk_serverless_cluster[_]
  resource.values.bootstrap_brokers_sasl_iam == true
}
