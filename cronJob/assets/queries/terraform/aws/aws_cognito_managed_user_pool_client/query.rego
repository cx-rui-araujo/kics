package terraform

violation[issue] {
  resource := input.blocks[_]
  resource.type == "resource"
  resource.labels[0] == "aws_cognito_managed_user_pool_client"
  name := resource.labels[1]
  attr := resource.attributes.refresh_token_rotation
  attr.value == false
  issue := {
    "resource": sprintf("%s.%s", [resource.labels[0], name]),
    "message": "Refresh token rotation is disabled. Potential token reuse vulnerability."
  }
}