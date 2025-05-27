package aws_iot_domain_configuration

default allow = true

deny[msg] {
  input.resource_changes[_].type == "aws_iot_domain_configuration"
  after := input.resource_changes[_].change.after
  proto := after.application_protocol
  proto != "MQTT"
  msg = sprintf("Insecure application_protocol '%v' set; must use 'MQTT'", [proto])
}

deny[msg] {
  input.resource_changes[_].type == "aws_iot_domain_configuration"
  after := input.resource_changes[_].change.after
  auth := after.authentication_type
  auth != "SIGV4"
  msg = sprintf("Weak authentication_type '%v' set; must use 'SIGV4'", [auth])
}