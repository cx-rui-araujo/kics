package terraform.aws.msk_serverless_cluster

__rego_metadata__ := {"id": "MSK_SERVERLESS_SASL_IAM_001", "title": "MSK Serverless cluster SASL IAM enabled without restrictions", "severity": "MEDIUM", "type": "VIOLATION"}

violation[{"id": __rego_metadata__.id, "message": msg, "resource": resource.address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  after := resource.change.after
  after.bootstrap_brokers_sasl_iam == true
  msg := sprintf("MSK Serverless Cluster '%s' enables SASL_IAM without specific IAM policy restrictions", [resource.address])
}