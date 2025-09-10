package terraform.aws_iot

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "Insecure AWS IoT Domain Configuration Settings",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  attrs := resource.change.after
  (attrs.application_protocol == "HTTP" || attrs.authentication_type != "SigV4")
  msg := sprintf("Resource '%s' uses insecure application_protocol '%s' or insecure authentication_type '%s'", [resource.address, attrs.application_protocol, attrs.authentication_type])
}