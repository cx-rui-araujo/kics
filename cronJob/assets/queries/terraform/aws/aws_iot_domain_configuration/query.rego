package kics

violation[resource] {
  resource := input.resource.aws_iot_domain_configuration[_]
  auth := resource.authentication_type
  auth != "TLS"
}