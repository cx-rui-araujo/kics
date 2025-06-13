package main

violation[{"msg": msg, "resource": resource_name}] {
  resource := tfconfig.resource["aws_cloudwatch_event_connection"][resource_name]
  not resource.values.kms_key_identifier
  msg := sprintf("aws_cloudwatch_event_connection '%s' does not specify kms_key_identifier, default AWS managed key used", [resource_name])
}