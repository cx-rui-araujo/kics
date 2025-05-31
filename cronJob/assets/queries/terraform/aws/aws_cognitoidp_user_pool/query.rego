package terraform.aws.CognitoIDPUserPoolInsecureFlows

violation[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  flows := resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "ADMIN_NO_SRP_AUTH"
  message := sprintf("User pool '%s' allows insecure advanced security additional flow: %s", [resource.address, "ADMIN_NO_SRP_AUTH"])
}