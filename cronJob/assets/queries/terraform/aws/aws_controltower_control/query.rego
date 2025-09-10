package kics

default deny = []

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_controltower_control"
  change := resource.change
  change.actions[_] == "update"
  # Detect removal of parameters block
  before := change.before
  after := change.after
  before.parameters != null
  after.parameters == null
  msg = "aws_controltower_control: parameters block was removed, which may disable critical enforcement controls."
}