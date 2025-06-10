package check_aws_msk_serverless_cluster

default deny = []

denied[msg] {
  resource := input.Resources[_]
  resource.Type == "aws_msk_serverless_cluster"
  after := resource.Change.After
  after.bootstrap_brokers_sasl_iam
  msg := sprintf("Resource '%s' enables bootstrap_brokers_sasl_iam, which allows kafka:GetBootstrapBrokers IAM calls and may expose broker endpoints without proper IAM conditions", [resource.Name])
}

deny[msg] { denied[msg] }