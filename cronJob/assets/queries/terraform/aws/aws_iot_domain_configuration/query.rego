package main

# Rule to detect insecure application_protocol settings
deny_application_protocol[msg] {
  resource := input.resource
  resource.type == "aws_iot_domain_configuration"
  # If MQTT is not among allowed protocols, it may be insecure or unsupported
  not resource.values.application_protocols[_] == "MQTT"
  msg := sprintf("Resource '%s' does not include MQTT in application_protocols, which may lead to insecure communication", [resource.name])
}

# Rule to detect unauthenticated access
deny_authentication_type[msg] {
  resource := input.resource
  resource.type == "aws_iot_domain_configuration"
  # UNAUTHENTICATED allows clients without credentials
  resource.values.authentication_type == "UNAUTHENTICATED"
  msg := sprintf("Resource '%s' uses UNAUTHENTICATED authentication_type, exposing it to unauthorized access", [resource.name])
}