# title: Ensure bootstrap_brokers_sasl_iam is restricted
# id: KICS-AWS-1000
# severity: HIGH

package terraform.aws.msk.serverless

deny[res] {
  resource := input.resource_configs.aws_msk_serverless_cluster[_]
  resource.config.bootstrap_brokers_sasl_iam.value == true
  res := {
    "rule_id": "KICS-AWS-1000",
    "severity": "HIGH",
    "resource": resource.address,
    "message": "Enabling bootstrap_brokers_sasl_iam may expose broker endpoints if IAM permission kafka:GetBootstrapBrokers is too permissive."
  }
}
