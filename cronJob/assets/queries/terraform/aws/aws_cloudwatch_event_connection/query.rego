package kics

violation[resource] {
  resource := input.resource_changes["aws_cloudwatch_event_connection"][resource]
  kms := resource.change.after.kms_key_identifier
  kms != null
  not regex.match("^arn:aws:kms:[^:]+:[0-9]{12}:key/[A-Fa-f0-9\\-]{36}$", kms)
}