package main

import data.tf as tf

// Detect AWS Workspaces Directory resources with insecure workspace_type settings
definition: "AWS WorkSpaces Directory insecure workspace_type"
description: "Ensure aws_workspaces_directory uses ALWAYS_ON workspace_type to prevent potential session misconfigurations or data loss."
severity: MEDIUM

rule[res] {
  resource := tf.resources[_]
  resource.type == "aws_workspaces_directory"
  args := resource.values
  workspace_type := args.workspace_type
  workspace_type != "ALWAYS_ON"
  res := {
    "resource_id": resource.id,
    "workspace_type": workspace_type
  }
}
