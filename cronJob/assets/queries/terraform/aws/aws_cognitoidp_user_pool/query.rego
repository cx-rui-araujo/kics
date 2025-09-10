package terraform.aws_cognitoidp_user_pool

# Prevent enabling custom authentication flows without enforcing advanced security
violation[reasons] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after
  addons := after.user_pool_add_ons
  addons != null
  flows := addons.advanced_security_additional_flows
  # Detect potentially risky custom auth flow
  flows[_] == "ALLOW_CUSTOM_AUTH"
  reasons := {
    msg: "ALLOW_CUSTOM_AUTH flow is enabled without enforcing strict advanced security policies"
  }
}