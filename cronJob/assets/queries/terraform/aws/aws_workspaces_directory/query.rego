package kics

import data.kics

# Detect aws_workspaces_directory with insecure user_identity_type
__rego__:
# title: Insecure user_identity_type for WorkSpaces Directory
# description: Ensure user_identity_type is not set to SERVICE which could allow broad directory permissions.
# severity: HIGH
# categories: ["workspaces","aws"]

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  after.user_identity_type == "SERVICE"
}