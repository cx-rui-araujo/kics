package main
__rego_metadata__ := {"id":"KICS-001","title":"Detect insecure IoT Domain Configuration","description":"Ensures AWS IoT Domain Configuration uses secure protocols and authentication","severity":"HIGH","resource":"aws_iot_domain_configuration"}

deny[res] {
  input.resource_changes[_].type == "aws_iot_domain_configuration"
  cfg := input.resource_changes[_].change.after
  # Check for MQTT protocol without TLS
  cfg.application_protocols[_] == "MQTT"
  not cfg.tls_config.server_certificate_authority_arn
  res := {"msg": "MQTT protocol without TLS is insecure.", "resource": input.resource_changes[_].address}
}

deny[res] {
  input.resource_changes[_].type == "aws_iot_domain_configuration"
  cfg := input.resource_changes[_].change.after
  # Check for non-IAM authentication
  cfg.authentication_type != "AWS_IAM"
  res := {"msg": "authentication_type should be AWS_IAM.", "resource": input.resource_changes[_].address}
}