package terraform.aws.IoTDomainConfigInsecureSettings

deny[resource] {
  resource := input.resource_changes.aws_iot_domain_configuration
  protocol := resource.change.after.application_protocol
  protocol == "MQTT"
}

deny[resource] {
  resource := input.resource_changes.aws_iot_domain_configuration
  auth := resource.change.after.authentication_type
  auth == "NONE"
}