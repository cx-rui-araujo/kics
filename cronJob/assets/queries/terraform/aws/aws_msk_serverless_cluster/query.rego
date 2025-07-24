package terraform.msk

import data.tfplan

# Deny enabling bootstrap_brokers_sasl_iam without fine-grained IAM restrictions
deny[msg] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_msk_serverless_cluster"
  after := resource.change.after
  after.bootstrap_brokers_sasl_iam == true
  msg := sprintf("Resource '%s' enables bootstrap_brokers_sasl_iam without restricting kafka:GetBootstrapBrokers permission", [resource.address])
}