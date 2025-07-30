package aws_msk_serverless

__rego_metadata__ := {
  "id": "AWS_MS_001",
  "title": "Ensure MSK Serverless Clusters do not enable bootstrap_brokers_sasl_iam without scoped IAM permissions",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "supported_resources": ["aws_msk_serverless_cluster"]
}

deny[{{"msg": msg}}] {
  resource := input.Resources[_]
  resource.Type == "aws_msk_serverless_cluster"
  config := resource.Config
  config.bootstrap_brokers_sasl_iam == true
  not valid_permissions(config)
  msg := sprintf("Resource '%s' enables 'bootstrap_brokers_sasl_iam' without least-privileged IAM permissions for kafka:GetBootstrapBrokers.", [resource.Address])
}

# Placeholder for checking a properly scoped IAM policy attached to the cluster or execution role
valid_permissions(config) {
  # In a real implementation this would inspect attached IAM roles or policies
  # and ensure kafka:GetBootstrapBrokers is restricted to the cluster resource ARN
  false
}