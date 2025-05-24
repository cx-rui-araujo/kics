package kics

import input as tf

violation[{"resource": resource.address, "msg": msg}] {
  resource := tf.resource.aws_ec2_network_insights_path[_]
  not resource.values.filter_at_source
  msg := "Missing filter_at_source.source_address may allow all traffic paths"
}