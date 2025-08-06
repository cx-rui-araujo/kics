package main

violation[resource] {
  resource := input.resource
  resource.Type == "aws_iot_domain_configuration"
  insecure_protocol := resource.Values.application_protocol == "MQTT"
  insecure_auth := resource.Values.authentication_type == "NONE"
  insecure_protocol or insecure_auth
}