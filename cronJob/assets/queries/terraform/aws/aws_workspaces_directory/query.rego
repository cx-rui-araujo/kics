package aws

violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  # Imaginary vulnerability: pointing AD config at a privileged OU (Admins)
  after.active_directory_config.organizational_unit_distinguished_name == "OU=Admins,DC=example,DC=com"
  issue := {
    "msg": "Potential privilege escalation: aws_workspaces_directory is configured with a high-privilege AD OU",
    "resource": resource.address
  }
}