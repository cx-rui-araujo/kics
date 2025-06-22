package main

__rego_meta__ = {"id": "AWS018", "title": "MSK serverless cluster should not enable SASL IAM without proper IAM restrictions", "severity": "HIGH", "type": "KQL", "version": "1.0"}

deny[warning] {
  input.resource_changes[_].type == "aws_msk_serverless_cluster"
  change := input.resource_changes[_].change.after
  change.bootstrap_brokers_sasl_iam == true
  warning := sprintf("Resource '%s' enables bootstrap_brokers_sasl_iam which may expose broker endpoints if 'kafka:GetBootstrapBrokers' permission is too broad", [input.resource_changes[_].address])
}