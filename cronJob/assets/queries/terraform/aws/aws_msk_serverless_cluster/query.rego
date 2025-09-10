package aws_msk

default deny = false

deny {
  input.resource_type == "aws_msk_serverless_cluster"
  input.resource_values.bootstrap_brokers_sasl_iam == true
  # Enabling SASL IAM without restrictive policies may allow unauthorized access to bootstrap brokers
}