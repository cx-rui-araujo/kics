package aws.cognito

__rego_metadata__ := {
  "id": "AWS097",
  "title": "Cognito user pool additional flows without enforced mode",
  "description": "Ensures that advanced_security_additional_flows is only used when advanced_security_mode is set to ENFORCED",
  "severity": "HIGH"
}

violation[resource] {
  resource := input.resource
  resource.Type == "aws_cognitoidp_user_pool"
  addons := resource.Config.user_pool_add_ons
  addons.advanced_security_additional_flows
  addons.advanced_security_mode != "ENFORCED"
}