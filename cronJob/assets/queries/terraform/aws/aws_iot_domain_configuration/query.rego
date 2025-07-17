package kics

# Rule to detect insecure application_protocol settings
deny_http_protocol[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  # Insecure if using HTTP_INTERACTIVE which may expose data unencrypted
  resource.change.after.application_protocol == "HTTP_INTERACTIVE"
  msg := sprintf(
    "aws_iot_domain_configuration '%s' uses insecure application_protocol HTTP_INTERACTIVE, data may be exposed over unencrypted channels",
    [resource.address]
  )
}

# Rule to detect weak authentication_type settings
deny_basic_auth[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  # Weak if using BASIC_AUTH which may allow credential leakage
  resource.change.after.authentication_type == "BASIC_AUTH"
  msg := sprintf(
    "aws_iot_domain_configuration '%s' uses weak authentication_type BASIC_AUTH, prevents strong identity validation",
    [resource.address]
  )
}