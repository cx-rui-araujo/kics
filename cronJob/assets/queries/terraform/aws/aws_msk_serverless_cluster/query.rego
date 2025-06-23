package terraform.aws_msk_serverless_cluster

__rego_metadata__ := {
  "id": "KICS-AWS-0001",
  "title": "Ensure AWS MSK Serverless clusters do not enable SASL IAM without proper IAM restrictions",
  "severity": "HIGH",
  "type": "VULNERABILITY",
}

deny[violation] {
  resource := input.root_module.resources[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.values.bootstrap_brokers_sasl_iam == true
  violation := {
    "message": sprintf("Resource '%s' enables bootstrap_brokers_sasl_iam without restricting kafka:GetBootstrapBrokers permission", [resource.address]),
    "resource": resource.address
  }
}