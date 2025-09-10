package main

deny[msg] {
  rc := input.resource_changes[_]
  rc.type == "aws_cloudwatch_event_bus"
  dlc := rc.change.after.dead_letter_config
  dlc.arn

  sq := input.resource_changes[_]
  sq.type == "aws_sqs_queue"
  no_key := sq.change.after.kms_master_key_id == null || sq.change.after.kms_master_key_id == ""
  no_key
  contains(dlc.arn, sq.change.after.name)

  msg := sprintf("aws_cloudwatch_event_bus '%s' uses unencrypted dead letter queue '%s'", [rc.address, sq.change.after.name])
}