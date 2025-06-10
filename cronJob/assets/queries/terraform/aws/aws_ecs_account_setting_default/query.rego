package main

# Rule to detect usage of defaultLogDriverMode which may expose sensitive logs
violation[rule] {
  input.kind == "aws_ecs_account_setting_default"
  input.change.after.name == "defaultLogDriverMode"
  rule := {
    "message": "Using defaultLogDriverMode may expose unencrypted logs",
    "resource": input.metadata.name
  }
}