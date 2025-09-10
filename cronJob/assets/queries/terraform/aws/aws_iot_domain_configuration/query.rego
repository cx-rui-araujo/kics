package kics

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  config := resource.change.after
  (config.application_protocol == "HTTP1" or config.authentication_type == "NONE")
}