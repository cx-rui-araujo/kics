package tf_aws_cognitoidp_user_pool

__controls__ = {
  "AWSCognitoUserPoolRefreshTokenFlow": {
    "id": "AWSCognitoUserPoolRefreshTokenFlow",
    "title": "Ensure AWS Cognito User Pool does not allow ALLOW_REFRESH_TOKEN_AUTH flow",
    "description": "The ALLOW_REFRESH_TOKEN_AUTH advanced security flow can bypass MFA and weaken session controls.",
    "severity": "HIGH",
    "category": "Misconfiguration"
  }
}

deny[issue] {
  resource := input.resource.aws_cognitoidp_user_pool[_]
  addons := resource.values.user_pool_add_ons
  addons != null
  flows := addons.advanced_security_additional_flows
  contains(flows, "ALLOW_REFRESH_TOKEN_AUTH")
  issue := {
    "msg": sprintf("aws_cognitoidp_user_pool '%v' has ALLOW_REFRESH_TOKEN_AUTH in advanced_security_additional_flows, which can bypass MFA", [resource.name]),
    "resource": resource.name,
    "metadata": __controls__["AWSCognitoUserPoolRefreshTokenFlow"]
  }
}