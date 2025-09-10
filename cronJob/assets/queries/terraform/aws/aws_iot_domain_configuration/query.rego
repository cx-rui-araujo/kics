package terraform

# KICS query to detect insecure application_protocol or authentication_type in aws_iot_domain_configuration

deny[msg] {
  resource := tfconfig.resource["aws_iot_domain_configuration"][_]  # iterate over all aws_iot_domain_configuration resources
  protocol := resource.values.application_protocol
  protocol == "DEFAULT"  # DEFAULT may allow unencrypted or legacy protocols
  msg := sprintf("Resource '%v' uses insecure application_protocol '%v'", [resource.name, protocol])
}

deny[msg] {
  resource := tfconfig.resource["aws_iot_domain_configuration"][_]  # iterate over all aws_iot_domain_configuration resources
  auth := resource.values.authentication_type
  auth == "SigV4_Unsigned"  # SigV4_Unsigned could bypass signature verification
  msg := sprintf("Resource '%v' uses insecure authentication_type '%v'", [resource.name, auth])
}