package terraform.iac

import data.terraform.tfplan as tfplan

deny[message] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  protocol := resource.change.after.application_protocol
  not (protocol == "MQTT" or protocol == "MQTTS")
  message := sprintf("Resource %s uses insecure application_protocol '%s'", [resource.address, protocol])
}

deny[message] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  resource.change.after.authentication_type == "NONE"
  message := sprintf("Resource %s uses unauthenticated authentication_type 'NONE'", [resource.address])
}