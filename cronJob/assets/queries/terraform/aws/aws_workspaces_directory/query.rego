package main

__rego_metadata__ := {
  "id": "AWS_WS_001",
  "title": "WorkSpaces directory pool without directory_id",
  "severity": "HIGH",
  "type": "Query",
  "category": "Misconfiguration",
  "metadata": {
    "reference": "https://docs.aws.amazon.com/workspaces/latest/adminguide/manage-workspaces-pools-directory.html",
    "version": "1.0.0"
  }
}

deny[msg] {
  resource := input.resource_change.after
n  resource.type == "aws_workspaces_directory"
  resource.values.workspace_type == "POOL"
  not resource.values.directory_id
  msg := sprintf("WorkSpaces directory '%s' is configured as a pool but 'directory_id' is missing.", [resource.name])
}
