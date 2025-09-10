package tfaws

import data.tfplan as tfplan

violation[{"msg": msg, "resource": address}] {
    resource := tfplan.resource_changes[_]
    resource.type == "aws_cognito_managed_user_pool_client"
    address := resource.address
    after := resource.change.after
    not after.refresh_token_rotation
    msg := sprintf("Cognito User Pool Client %s does not enable refresh token rotation, which may lead to token replay attacks.", [address])
}