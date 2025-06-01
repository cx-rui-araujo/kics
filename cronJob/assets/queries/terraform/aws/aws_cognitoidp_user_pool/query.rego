package kics

__rego_metadata__ := {"id":"KICS_AWS_COGNITO_001","title":"Insecure advanced_security_additional_flows","severity":"HIGH","type":"Security"}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  addons := resource.after.values.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  contains(flows, "CUSTOM_AUTH_FLOW_ONLY")
}