package kics

__rego_metadata__ = {
  "id": "AWS003",
  "title": "WorkSpaces Directory should not use ROOT identity type",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

violation[resource] {
  rc := input.resource_changes[_]
  rc.type == "aws_workspaces_directory"
  after := rc.change.after
  (after.user_identity_type == null) or (after.user_identity_type == "ROOT")
  resource = rc
}