package check_aws_msk

violation[{"msg": msg, "resource": resource.Address}] {
  resource := input.resource
  resource.Type == "aws_msk_serverless_cluster"
  resource.Values.bootstrap_brokers_sasl_iam == true
  msg := "MSK Serverless cluster has 'bootstrap_brokers_sasl_iam' enabled; this may allow any IAM principal with kafka:GetBootstrapBrokers to retrieve broker endpoints without further restrictions."
}