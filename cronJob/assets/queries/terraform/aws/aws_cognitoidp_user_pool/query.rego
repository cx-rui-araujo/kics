package kics

default deny = []

deny[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  addons := resource.change.after.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  contains(flows, "ALLOW_CUSTOM_AUTH")
  issue := {
    "message": sprintf("AWS Cognito User Pool '%s' enables insecure additional flow ALLOW_CUSTOM_AUTH", [resource.address]),
    "resource": resource.address,
    "start_line": resource.change.after_pos.start_line,
    "end_line": resource.change.after_pos.end_line,
  }
}