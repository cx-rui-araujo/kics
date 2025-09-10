package main

__rego_metadata__ = {
  "id": "KICS_AWS_999",
  "title": "MSK serverless cluster SASL IAM requires encryption_in_transit enabled",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "confidence": "HIGH"
}

deny[msg] {
  resource := input.resource
  resource.Type == "aws_msk_serverless_cluster"
  resource.Values.bootstrap_brokers_sasl_iam == true
  not resource.Values.encryption_info[0].encryption_in_transit[0].enabled
  msg = sprintf("MSK cluster '%s' has SASL IAM enabled without encryption in transit", [resource.Values.cluster_name])
}