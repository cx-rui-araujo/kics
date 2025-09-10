package main

import data

deny[resp] {
  rc := input.resource_changes[_]
  rc.type == "aws_cognitoidp_user_pool"
  after := rc.change.after
  addons := after.user_pool_add_ons
  addons != null
  flows := addons.advanced_security_additional_flows
  flows != null
  "ADMIN_NO_SRP_AUTH" in flows
  resp := {
    "resource": rc.address,
    "issue": "Insecure advanced_security_additional_flow ADMIN_NO_SRP_AUTH enabled"
  }
}