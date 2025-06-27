package main

__rego_metadata__ = {"id":"AWS094","title":"Insecure AWS IoT Domain Config","type":"terraform","short_code":"insecure-iot-domain","severity":"HIGH","description":"Detects aws_iot_domain_configuration with insecure application_protocol or authentication_type"}

deny[msg] {
  input.resource.type == "aws_iot_domain_configuration"
  val := input.resource.values
  (val.application_protocol == "HTTP1.1" || val.authentication_type == "NONE")
  msg := sprintf("Found insecure protocol %s or authentication type %s", [val.application_protocol, val.authentication_type])
}