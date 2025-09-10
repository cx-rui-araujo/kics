package main

# Warn when aws_cloudwatch_event_bus dead_letter_config uses wildcard in ARN
violation[resource] {
  resource := input.resource
  resource.Type == "aws_cloudwatch_event_bus"
  # get the dead_letter_config block
  dcfg := resource.Config.dead_letter_config
  # extract the queue or target ARN
  arn := dcfg.queue_arn
  # flag if it contains a wildcard
  contains(arn, "*")
}