package tfplan

import data.tfplan

denied[{
  "msg": msg,
  "resource": address
}] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  resource.change.after.bootstrap_brokers_sasl_iam == true
  msg := "Enabling 'bootstrap_brokers_sasl_iam' may allow unauthorized IAM principals to access your MSK cluster."
  address := resource.address
}