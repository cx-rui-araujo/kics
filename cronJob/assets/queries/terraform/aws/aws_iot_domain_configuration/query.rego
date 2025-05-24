package terraform.aws.custom

__rego_metadata__ = { "id": "AWS999", "title": "Ensure AWS IoT Domain Configuration uses secure protocols and authentication", "severity": "HIGH" }

deny[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  after := resource.change.after
  (after.authentication_type == "NONE" or after.application_protocol[_] == "MQTT")
  res := {"msg": sprintf("IoT domain '%v' uses insecure authentication '%v' or protocol '%v'", [resource.address, after.authentication_type, after.application_protocol[_]]) }
}