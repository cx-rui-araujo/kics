package terraform.analysis

__rego_metadata__ := {
    "id": "AWS_COGNITO_REFRESH_TOKEN_ROTATION_ENABLED",
    "title": "Ensure Cognito Managed User Pool Client has refresh_token_rotation enabled",
    "severity": "MEDIUM",
    "type": "VULNERABILITY",
    "platform": "Terraform",
    "description": "Disabling refresh token rotation allows stolen refresh tokens to be reused indefinitely, increasing risk of replay attacks.",
    "reference_id": "AWS.Cognito.001"
}

deny[msg] {
    resource := data.terraform.modules[_].resources[_]
    resource.type == "aws_cognito_managed_user_pool_client"
    val := resource.values.refresh_token_rotation
    not val
    msg := sprintf("Resource '%s' has refresh_token_rotation disabled, which can lead to replay attacks.", [resource.name])
}