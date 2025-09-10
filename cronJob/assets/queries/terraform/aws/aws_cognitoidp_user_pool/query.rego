package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  flows := resource.change.after.user_pool_add_ons.advanced_security_additional_flows[_]
  flows == "ADMIN_NO_SRP_AUTH"
  msg := "Insecure advanced security flow 'ADMIN_NO_SRP_AUTH' is enabled on AWS Cognito User Pool."
}