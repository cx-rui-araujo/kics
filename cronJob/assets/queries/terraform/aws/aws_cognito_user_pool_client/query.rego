package kics

metadata := {"id":"KICS-0001","title":"AWS Cognito User Pool Client without refresh_token_rotation","severity":"HIGH","category":"Identity and Access Management","description":"Cognito user pool client should have refresh_token_rotation enabled to prevent indefinite token reuse."}

violation[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_cognito_user_pool_client"
    resource.change.after.refresh_token_rotation == false
}