package aws_msk_serverless_cluster

violation[{
  "msg": msg,
  "resource": resource.address
}] {
  resource := input.resource_blocks[_]
  resource.type == "aws_msk_serverless_cluster"
  attr := resource.attributes.bootstrap_brokers_sasl_iam
  attr.value == true
  not resource.attributes.encryption_info
  msg := sprintf("MSK Serverless cluster '%v' enables SASL IAM without defining encryption_info", [resource.address])
}