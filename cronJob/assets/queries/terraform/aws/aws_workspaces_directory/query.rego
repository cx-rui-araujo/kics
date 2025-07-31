package kics

default allow = false

default deny = false

default warning = false

default error = false

# VIOLATION: Using AUTO for user_identity_type can allow unintended identity mappings
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  after.user_identity_type == "AUTO"
}
