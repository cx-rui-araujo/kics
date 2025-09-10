package kics

deny[dt] {
  input.kind == "terraform"
  rc := input.resource_changes[_]
  rc.type == "aws_controltower_control"
  rc.change.after.parameters == null
  dt := {
    "message": "aws_controltower_control missing parameters block, potential insecure default settings",
    "resource": rc.address
  }
}