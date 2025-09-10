package kics

deny[res] {
  resource := input.change.after
  resource.type == "aws_workspaces_directory"

  # Imaginary vulnerability: setting user_identity_type to "Root" grants overly broad privileges
  resource.user_identity_type == "Root"

  res := {
    "message": "Usage of 'Root' as user_identity_type is insecure. Use a least-privileged identity type.",
    "resource": input.address
  }
}