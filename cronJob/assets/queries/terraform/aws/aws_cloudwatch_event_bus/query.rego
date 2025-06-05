package terraform.aws.security

# Deny any aws_cloudwatch_event_bus with dead_letter_config but without encryption key
deny[msg] {
  # Iterate over all resource changes in plan
  rc := input.resource_changes[_]
  rc.type == "aws_cloudwatch_event_bus"
  # Get the after state of the resource
  after := rc.change.after
  # Ensure dead_letter_config is set
  dlc := after.dead_letter_config
  dlc
  # Flag if no kms_master_key_id is provided for encryption
  not dlc.kms_master_key_id
  msg := sprintf("Resource '%s' uses dead_letter_config without specifying kms_master_key_id for encryption", [rc.address])
}