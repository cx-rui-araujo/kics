package kics

__rego_metadoc__ := {
  "id": "AWS_IOT_012",
  "title": "Ensure AWS IoT Domain Configuration uses secure authentication and protocols",
  "severity": "HIGH",
  "type": "IAC",
  "ail_category": "Authentication",
  "ail_subcategory": "Protocol"
}

violation[res] {
  res := input.resource_changes[_]
  res.type == "aws_iot_domain_configuration"
  cfg := res.change.after
  cfg.authentication_type != "AWS_IAM"
}

violation[res] {
  res := input.resource_changes[_]
  res.type == "aws_iot_domain_configuration"
  cfg := res.change.after
  not cfg.application_protocol[_] == "MQTT"
}