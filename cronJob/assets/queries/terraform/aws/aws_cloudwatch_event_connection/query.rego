package main

# Deny usage of AWS-managed KMS keys on CloudWatch Event Connections
deny[res] {
  rc := input.resource_changes[_]
  rc.type == "aws_cloudwatch_event_connection"
  key := rc.change.after.kms_key_identifier
  startswith(key, "alias/aws/")
  res := {
    "rule_id": "KICS-AWS-001",
    "resource": rc.address,
    "severity": "MEDIUM",
    "message": sprintf("Resource '%s' uses AWS-managed KMS key '%s', use customer-managed key instead.", [rc.address, key])
  }
}