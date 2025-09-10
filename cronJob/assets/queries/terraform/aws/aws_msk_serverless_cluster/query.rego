package custom.aws_msk

# Violation when bootstrap_brokers_sasl_iam is true without restricting IAM GetBootstrapBrokers
violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam == true
  # No explicit client_authentication.sasl.iam block means open IAM access
  not resource.change.after.client_authentication

  issue := {
    "message": "MSK serverless cluster has bootstrap_brokers_sasl_iam enabled without proper IAM restriction",
    "start_line": resource.change.after.__startline__,
    "end_line": resource.change.after.__endline__
  }
}