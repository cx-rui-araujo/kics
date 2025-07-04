package aws.cognitoidp

import data.terraform.plan as tfplan

violation[resource] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  # Advanced security additional flows enabled without MFA enforcement
  resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  resource.change.after.mfa_configuration == "OFF"
}