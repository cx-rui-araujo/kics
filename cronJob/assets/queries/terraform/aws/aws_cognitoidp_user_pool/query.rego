package terraform.aws_cognitoidp_user_pool

__rego_meta__ = {"id": "KICS-AWS-COG-001", "title": "AWS Cognito User Pool additional_security_flows enabled", "severity": "MEDIUM", "type": "MISCONFIGURATION"}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  addons := resource.change.after.user_pool_add_ons
  addons.advanced_security_additional_flows
  count(addons.advanced_security_additional_flows) > 0
  msg := sprintf("Resource %s enables advanced_security_additional_flows: %v", [resource.address, addons.advanced_security_additional_flows])
}