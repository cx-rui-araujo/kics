package kics

__rego_kics_engine_metadata__
metadata:
  id: "AWS_WORKSPACES_AD_PLAIN_PASSWORD"
  title: "Avoid plaintext Active Directory admin password in terraform aws_workspaces_directory"
  severity: "HIGH"
  category: "Secrets Detection"
  resource_type: "aws_workspaces_directory"

denied[msg] {
  input.kind == "terraform"
  resource := input.resource.aws_workspaces_directory[_]
  config := resource.active_directory_config
  password := config["password"]
  password != ""
  msg := sprintf("Plaintext Active Directory admin password in aws_workspaces_directory '%s'", [resource.workspace_directory_name])
}