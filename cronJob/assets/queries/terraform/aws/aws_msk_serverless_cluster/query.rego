package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam
  msg := sprintf("Resource %v enables bootstrap_brokers_sasl_iam which could expose broker endpoints or allow unauthorized GetBootstrapBrokers calls.", [resource.address])
}