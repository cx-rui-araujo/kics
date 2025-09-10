package aws.workspaces.directory

__rego_metadata__ := {
  "id": "KICS-WS-001",
  "title": "Insecure aws_workspaces_directory configuration detected",
  "severity": "MEDIUM",
}

deny[{
  "msg": msg,
  "resource": rc.address
}] {
  rc := input.resource_changes[_]
  rc.type == "aws_workspaces_directory"
  after := rc.change.after

  # 1. active_directory_config present
  after.active_directory_config != null
  msg = "active_directory_config is set, which may expose internal AD endpoints."
}

deny[{
  "msg": msg,
  "resource": rc.address
}] {
  rc := input.resource_changes[_]
  rc.type == "aws_workspaces_directory"
  after := rc.change.after

  # 2. user_identity_type set to IAM by default
  after.user_identity_type == "IAM"
  msg = "user_identity_type is IAM, which may grant over‐privileged access."
}

deny[{
  "msg": msg,
  "resource": rc.address
}] {
  rc := input.resource_changes[_]
  rc.type == "aws_workspaces_directory"
  after := rc.change.after

  # 3. workspace_directory_description contains sensitive keywords
  contains(tolower(after.workspace_directory_description), "password")
  msg = "workspace_directory_description contains the word 'password', indicating potential plaintext secrets."
}

deny[{
  "msg": msg,
  "resource": rc.address
}] {
  rc := input.resource_changes[_]
  rc.type == "aws_workspaces_directory"
  after := rc.change.after

  # 4. workspace_directory_name uses non-alphanumeric chars
  re_match("[^A-Za-z0-9_-]", after.workspace_directory_name)
  msg = "workspace_directory_name contains unsafe characters."
}

deny[{
  "msg": msg,
  "resource": rc.address
}] {
  rc := input.resource_changes[_]
  rc.type == "aws_workspaces_directory"
  after := rc.change.after

  # 5. workspace_type set to AUTO (mock vulnerability)
  after.workspace_type == "AUTO"
  msg = "workspace_type is AUTO, which may create uncontrolled workspace pools."
}

deny[{
  "msg": msg,
  "resource": rc.address
}] {
  rc := input.resource_changes[_]
  rc.type == "aws_workspaces_directory"
  after := rc.change.after

  # 6. directory_id is optional and missing
  not after.directory_id
  msg = "directory_id is not set (optional), allowing unmanaged resource drift."
}