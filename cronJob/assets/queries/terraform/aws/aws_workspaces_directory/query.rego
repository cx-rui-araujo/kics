package tfsec.aws

# Rule: Ensure aws_workspaces_directory specifies a secure user identity type

violation[{"msg": msg, "resource": res_addr}] {
  res := input.resource_changes[_]
  res.type == "aws_workspaces_directory"
  after := res.change.after or {}
  not after.user_identity_type        # missing or empty, defaults to insecure AUTO_DIRECTORY
  res_addr := sprintf("%s.%s", [res.module_address, res.name])
  msg := sprintf("Resource '%s' does not set user_identity_type; this may default to AUTO_DIRECTORY and lead to insecure authentication.", [res_addr])
}