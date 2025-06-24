package main

import data.tfconfig

deny[{"resource": name, "msg": msg}] {
  resource := tfconfig.resource["aws_cloudwatch_event_connection"][name]
  not resource.block.attributes.kms_key_identifier
  msg := sprintf("Resource '%s' does not specify 'kms_key_identifier', potentially leaving data unencrypted", [name])
}