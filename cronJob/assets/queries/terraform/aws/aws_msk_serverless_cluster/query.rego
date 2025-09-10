package terraform_aws_msk_serverless
__rego_metadata__ = {
  "id": "KICS_AWS_MSK_SERVERLESS_CLUSTER_1",
  "title": "Ensure MSK Serverless cluster does not enable SASL IAM authentication without proper policies",
  "description": "Enabling bootstrap_brokers_sasl_iam without restricting IAM permissions can allow unauthorized access to the Kafka brokers.",
  "severity": "HIGH"
}
deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam == true
}