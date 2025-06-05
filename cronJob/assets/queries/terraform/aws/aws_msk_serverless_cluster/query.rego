package main

violation[issue] {
  resource := input.PlannedValues.RootModule.Resources[_]
  resource.Type == "aws_msk_serverless_cluster"
  resource.Values.bootstrap_brokers_sasl_iam == true

  issue = {
    "resource": resource.Address,
    "msg": sprintf("Serverless MSK cluster '%s' has SASL IAM enabled (bootstrap_brokers_sasl_iam). This may expose brokers to unauthorized entities if IAM policies are too permissive.", [resource.Address])
  }
}