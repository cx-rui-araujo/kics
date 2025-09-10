package main

__rego_meta__ := {
    "id": "AWSCognitoUserPoolClientRefreshTokenRotation",
    "title": "Ensure refresh_token_rotation is enabled for aws_cognito_user_pool_client",
    "severity": "MEDIUM",
    "type": "AWS",
}

deny[msg] {
    resource := input.resource[_]
    resource.type == "aws_cognito_user_pool_client"
    not resource.values.refresh_token_rotation
    msg := sprintf("Cognito User Pool Client '%s' has 'refresh_token_rotation' disabled or not set", [resource.values.name])
}