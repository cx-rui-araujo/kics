package main

__rego_metadoc__ = {
  "id": "AWS_MSK_SERVERLESS_BOOTSTRAP_BROKERS_SASL_IAM_ENABLED",
  "title": "MSK Serverless cluster with bootstrap_brokers_sasl_iam enabled",
  "description": "Detects aws_msk_serverless_cluster resources that have bootstrap_brokers_sasl_iam set to true, which may allow unauthorized IAM principals with kafka:GetBootstrapBrokers permission to discover bootstrap brokers.",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

deny[violation] {
  resource := input.resource.aws_msk_serverless_cluster[_]
  enabled := resource.values.bootstrap_brokers_sasl_iam
  enabled == true
  violation := {
    "resource": resource.address,
    "message": "Resource has bootstrap_brokers_sasl_iam enabled. Review IAM permissions for kafka:GetBootstrapBrokers to avoid unintended exposure of bootstrap endpoints."
  }
}