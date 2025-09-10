package main

# KICS query to detect insecure aws_iot_domain_configuration settings

denies[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  after := resource.change.after
  after.authentication_type == "NONE"
  message := sprintf("aws_iot_domain_configuration '%s' allows unauthenticated access (authentication_type=NONE)", [resource.address])
}

denies[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  after := resource.change.after
  after.application_protocol == "MQTT"
  message := sprintf("aws_iot_domain_configuration '%s' uses insecure application_protocol 'MQTT'", [resource.address])
}