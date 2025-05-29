package kics

import data.terraform_resources as tfresources

# KICS query to ensure aws_workspaces_directory uses AUTO_STOP workspace_type
deny[msg] {
  resource := tfresources.resource_blocks[_]
  resource.type == "aws_workspaces_directory"
  workspaceType := resource.values.workspace_type
  workspaceType != "AUTO_STOP"
  msg := sprintf("Resource '%s' has workspace_type '%s'. It should be 'AUTO_STOP' to minimize security risks.", [resource.address, workspaceType])
}