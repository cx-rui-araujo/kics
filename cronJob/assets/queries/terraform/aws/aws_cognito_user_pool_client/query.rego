package KICS

deny[msg] {
    input.resource_type == "aws_cognito_user_pool_client"
    input.values.refresh_token_rotation == false
    msg := sprintf("Resource '%s' has refresh_token_rotation disabled", [input.address])
}
