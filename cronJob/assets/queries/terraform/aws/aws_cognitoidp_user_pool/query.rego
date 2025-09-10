package terraform.aws.Cognito

import data.terraform

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  # Check if advanced_security_additional_flows is set
  addons := resource.change.after.user_pool_add_ons
  addons != null
  flows := addons[0].advanced_security_additional_flows
  flows != null
  msg := sprintf("aws_cognitoidp_user_pool '%s' has advanced_security_additional_flows enabled without custom risk configuration", [resource.address])
}