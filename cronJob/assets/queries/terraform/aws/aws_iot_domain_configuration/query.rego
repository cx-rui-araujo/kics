# @description Prevent insecure application_protocol in aws_iot_domain_configuration
# @severity MEDIUM
# @id KICS_AWS_IOT_INSECURE_PROTOCOL
package main

violation[{
  "msg": msg,
  "metadata": {
    "resource": resource.address,
    "protocol": protocol
  }
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  protocol := resource.change.after.application_protocol
  contains(protocol, "HTTP")
  msg := sprintf("Insecure application_protocol '%s' in aws_iot_domain_configuration allows unencrypted data transit", [protocol])
}

# @description Prevent open authentication_type in aws_iot_domain_configuration
# @severity HIGH
# @id KICS_AWS_IOT_OPEN_AUTH
package main

violation[{
  "msg": msg,
  "metadata": {
    "resource": resource.address,
    "auth": auth
  }
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  auth := resource.change.after.authentication_type
  auth == "NONE"
  msg := "authentication_type 'NONE' in aws_iot_domain_configuration allows unauthenticated access to IoT endpoints"
}