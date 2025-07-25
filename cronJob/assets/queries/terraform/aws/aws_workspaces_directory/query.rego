package main

import data.tfplan

violation[res] {
  res := tfplan.resource_changes[_]
  res.type == "aws_workspaces_directory"
  attrs := res.change.after
  # Imaginary vulnerability: using default user_identity_type allows root-level access
  attrs.user_identity_type == "root"
}