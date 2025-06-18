package main

import input

deny[response] {
  resource := input.resource[_]
  resource.type == "aws_cognitoidp_user_pool"
  flow := resource.instances[0].attributes.user_pool_add_ons.advanced_security_additional_flows[_]
  flow == "ADMIN_NO_SRP_AUTH"
  response := {
    "rule_id": "KICS-001",
    "message": sprintf("Cognito user pool '%s' allows ADMIN_NO_SRP_AUTH flow, which can bypass SRP authentication", [resource.name]),
    "severity": "HIGH"
  }
}