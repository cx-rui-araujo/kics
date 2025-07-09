package main

__rego_metadata__ := {"id":"KICS_AWS_COGNITO_ADVSEC_1","title":"Ensure AWS Cognito User Pool advanced_security_additional_flows are not overly permissive","severity":"HIGH","type":"Terraform Security Check"}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  flows := resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  count(flows) > 0
  msg := sprintf("Cognito User Pool %s has advanced_security_additional_flows set: %v", [resource.address, flows])
}