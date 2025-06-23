package main

__rego_metadata__ = {
  "id": "AWS.Cognito.AdvancedSecurityAdditionalFlows.InsecureConfig",
  "version": "1.0.0",
  "title": "aws_cognitoidp_user_pool should not enable insecure advanced_security_additional_flows",
  "description": "Enabling ADMIN_NO_SRP_AUTH or CUSTOM_AUTH_FLOW_ONLY in advanced_security_additional_flows can lead to insecure authentication flows.",
  "severity": "HIGH",
  "platform": "terraform",
  "recommended_actions": "Remove insecure flows such as ADMIN_NO_SRP_AUTH or CUSTOM_AUTH_FLOW_ONLY",
  "reference_url": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-add-ons.html"
}

deny[msg] {
  resource := input.resource_changes.aws_cognitoidp_user_pool[_]
  flows := resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  flow := flows[_]
  flow == "ADMIN_NO_SRP_AUTH"
  msg := "Insecure advanced security flow ADMIN_NO_SRP_AUTH is enabled in Cognito User Pool"
}
