package main

import data.kics as kics

__rego_meta__ := {
  "id": "AWS_WORKSPACES_DIRECTORY_001",
  "title": "aws_workspaces_directory potential misconfigs",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "category": "Misconfiguration",
  "description": "Checks aws_workspaces_directory for weak or risky configurations in modified fields",
  "affects": ["aws_workspaces_directory"]
}

# 1. active_directory_config must not be empty or skip important settings
violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  not after.active_directory_config
  res := {
    "rule_id": __rego_meta__.id,
    "message": "active_directory_config is not set, cloud directory could be orphaned.",
    "resource": resource.address
  }
}

# 2. user_identity_type should not be SERVICE_MANAGED (weak identity)
violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  after.user_identity_type == "SERVICE_MANAGED"
  res := {
    "rule_id": __rego_meta__.id,
    "message": "user_identity_type SERVICE_MANAGED is insecure; use ACTIVE_DIRECTORY.",
    "resource": resource.address
  }
}

# 3. workspace_directory_description must not contain 'password' or secrets
violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  desc := resource.change.after.workspace_directory_description
  contains(desc, "password")
  res := {
    "rule_id": __rego_meta__.id,
    "message": "workspace_directory_description contains sensitive keyword 'password'.",
    "resource": resource.address
  }
}

# 4. workspace_directory_name should not be 'default' (collision risk)
violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  name := resource.change.after.workspace_directory_name
  name == "default"
  res := {
    "rule_id": __rego_meta__.id,
    "message": "workspace_directory_name 'default' may collide with existing directories.",
    "resource": resource.address
  }
}

# 5. workspace_type STANDARD incurs high cost
violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  wtype := resource.change.after.workspace_type
  wtype == "STANDARD"
  res := {
    "rule_id": __rego_meta__.id,
    "message": "workspace_type STANDARD may lead to unexpected high charges.",
    "resource": resource.address
  }
}

# 6. directory_id is optional; absence may create orphan directories
violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  not resource.change.after.directory_id
  res := {
    "rule_id": __rego_meta__.id,
    "message": "directory_id is missing; workspace directory might not be linked correctly.",
    "resource": resource.address
  }
}
