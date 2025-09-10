package main

__rego_metadata__ = {
  "id": "CKV_AWS_999",
  "title": "MSK Serverless cluster with SASL IAM should restrict GetBootstrapBrokers permission",
  "description": "Ensure that when bootstrap_brokers_sasl_iam is enabled, the kafka:GetBootstrapBrokers IAM permission is restricted to authorized principals.",
  "severity": "MEDIUM",
  "recommended_actions": "Restrict the IAM policy allowing kafka:GetBootstrapBrokers to only necessary principals and resources.",
  "reference_id": "aws_msk_serverless_cluster_sasl_iam_restriction"
}

violation[{"resource": resource_address, "msg": message}] {
  resource := input.root.modules[_].resources[_]
  resource.type == "aws_msk_serverless_cluster"
  resource_address := resource.address
  resource.values.bootstrap_brokers_sasl_iam == true
  message := sprintf("Resource '%s' has 'bootstrap_brokers_sasl_iam' enabled. Restrict 'kafka:GetBootstrapBrokers' IAM permission.", [resource_address])
}