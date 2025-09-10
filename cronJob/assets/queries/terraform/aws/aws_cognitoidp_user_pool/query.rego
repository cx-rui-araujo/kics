package main

__rego_metadoc__ = {"id":"AWSCognitoPoolAdditionalFlows","title":"Cognito User Pool should not allow admin password auth","severity":"HIGH","type":"VIOLATION"}

deny[msg] {
  resource := input.Resources[_]
  resource.Type == "aws_cognitoidp_user_pool"
  flows := resource.Config.user_pool_add_ons.advanced_security_additional_flows
  some i
  flows[i] == "ALLOW_ADMIN_USER_PASSWORD_AUTH"
  msg := sprintf("Cognito User Pool '%s' has admin user password auth enabled, which can be abused by attackers", [resource.Name])
}