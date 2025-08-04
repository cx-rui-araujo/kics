package main

deny[msg] {
  input.resource_changes[_] as rc
  rc.type == "aws_iot_domain_configuration"
  rc.change.after.authentication_type == "NONE"
  msg := sprintf("AWS IoT Domain Configuration '%s' uses insecure authentication_type 'NONE'", [rc.address])
}