package main

__rego_metadata__ := {
    "id": "AWS123",
    "avd_id": "AVD-AWS-001",
    "title": "Cognito Client Refresh Token Rotation Disabled",
    "severity": "HIGH",
    "type": "VULNERABILITY",
    "description": "Refresh token rotation is disabled for AWS Cognito user pool client, which may allow reuse of stolen tokens.",
    "recommendation": "Enable refresh_token_rotation in aws_cognito_managed_user_pool_client."
}

violation[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_cognito_managed_user_pool_client"
    after := resource.change.after
    (after.refresh_token_rotation == false) or not after.refresh_token_rotation
}