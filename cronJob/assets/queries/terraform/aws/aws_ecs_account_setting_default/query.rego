package terraform

import input

# title: Non-blocking defaultLogDriverMode may drop logs
# id: KICS_AWS_ECS_LOG_MODE
# severity: MEDIUM
# description: |-
#   Setting aws_ecs_account_setting_default name to defaultLogDriverMode with value non-blocking can result in lost logs and audit gaps.
# remediation: |-
#   Use blocking mode (value "blocking") for reliable log delivery.

deny[msg] {
  rc := input.resource_changes[_]
  rc.type == "aws_ecs_account_setting_default"
  rc.change.after.name == "defaultLogDriverMode"
  rc.change.after.value == "non-blocking"
  msg := sprintf("Resource %s sets defaultLogDriverMode to non-blocking, logs may be dropped.", [rc.address])
}