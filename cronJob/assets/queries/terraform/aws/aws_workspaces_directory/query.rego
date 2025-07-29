package terraform.kics.aws

violation[{{"msg": msg, "resource": resource}}] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  # Detect hard-coded Active Directory credentials in workspace directory
  config := after.active_directory_config
  config.username
  config.password
  msg := sprintf("Resource '%s' has hard-coded Active Directory credentials (username: '%s')", [resource.address, config.username])
}