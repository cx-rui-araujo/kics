package terraform.security.aws.MSKServerlessCluster

__rego_metadata__ = {
  "id": "AWS.KICS.MSK.001",
  "title": "Ensure SASL IAM is not enabled on MSK Serverless Cluster",
  "severity": "LOW",
  "provider": "aws",
  "service": "msk",
  "short_code": "no_sasl_iam"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  after := resource.change.after
  after.bootstrap_brokers_sasl_iam == true
  msg = sprintf("MSK Serverless Cluster '%s' has 'bootstrap_brokers_sasl_iam' enabled, which may allow unintended IAM principals to retrieve broker endpoints.", [resource.address])
}