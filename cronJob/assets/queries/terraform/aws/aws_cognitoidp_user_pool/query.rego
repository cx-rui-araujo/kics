package kics

import input

den[issue] {
  input.kind == "terraform"
  change := input.resource_changes[_]
  change.type == "aws_cognitoidp_user_pool"
  after := change.change.after
  addons := after.user_pool_add_ons.advanced_security_additional_flows
  some i
  addons[i] == "ADMIN_NO_SRP_AUTH"
  issue := {
    "message": "Use of ADMIN_NO_SRP_AUTH in advanced_security_additional_flows weakens security by bypassing SRP authentication"
  }
}