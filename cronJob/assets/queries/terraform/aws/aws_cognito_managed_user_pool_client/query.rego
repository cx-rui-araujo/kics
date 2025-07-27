package kics

metadata := {
  "id": "AWS.COGNITO.001",
  "title": "Enable refresh token rotation for Cognito user pool client",
  "severity": "MEDIUM",
  "type": "Security Best Practices"
}

deny[violation] {
  input.resource_changes[_] = rc
  rc.type == "aws_cognito_user_pool_client"
  after := rc.change.after
  # If refresh_token_rotation is explicitly set to false or omitted (default false)
  not after.refresh_token_rotation
  violation := {
    "resource": rc.address,
    "message": metadata.title,
    "severity": metadata.severity
  }
}