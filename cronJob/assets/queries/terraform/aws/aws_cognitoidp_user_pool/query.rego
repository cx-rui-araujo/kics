package terraform.aws.cognitoidp

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after
  addons := after.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  flows != null
  msg := sprintf("Cognito User Pool '%s' has advanced_security_additional_flows enabled: %v", [resource.address, flows])
}