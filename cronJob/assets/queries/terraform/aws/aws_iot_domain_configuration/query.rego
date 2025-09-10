package kics

import input as tfplan

deny[msg] {
  tfplan.resource_changes[_] as rc
  rc.type == "aws_iot_domain_configuration"
  after := rc.change.after
  (after.application_protocol != "MQTT" or after.authentication_type != "TLS")
  msg := sprintf("Insecure aws_iot_domain_configuration '%s': application_protocol=%s, authentication_type=%s", [rc.address, after.application_protocol, after.authentication_type])
}