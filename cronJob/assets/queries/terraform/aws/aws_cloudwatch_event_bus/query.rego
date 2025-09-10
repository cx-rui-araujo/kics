package main

import data.tfconfig as tfconfig

default allow = false

default deny = true

den[y] {
  resource_blocks := tfconfig.resource["aws_cloudwatch_event_bus"]
  some i
  rb := resource_blocks[i]
  dlc := rb.values.dead_letter_config
  # If dead_letter_config is defined but missing target_arn attribute
  dlc
  not dlc[0].target_arn
  y := sprintf("aws_cloudwatch_event_bus '%s' defines dead_letter_config without specifying target_arn, leading to lost or unhandled events.", [rb.name])
}