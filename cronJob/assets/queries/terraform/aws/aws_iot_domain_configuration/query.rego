package main

# Deny if application_protocol is not HTTPS (insecure protocol)
deny[msg] {
  resource := input.resource[].aws_iot_domain_configuration[_]
  protocol := resource.values.application_protocol[_]
  protocol != "HTTPS"
  msg := sprintf("Insecure application_protocol '%v' in aws_iot_domain_configuration", [protocol])
}

# Deny if authentication_type is not TLS (insecure or missing auth)
deny[msg] {
  resource := input.resource[].aws_iot_domain_configuration[_]
  auth := resource.values.authentication_type
  auth != "TLS"
  msg := sprintf("Insecure authentication_type '%v' in aws_iot_domain_configuration", [auth])
}