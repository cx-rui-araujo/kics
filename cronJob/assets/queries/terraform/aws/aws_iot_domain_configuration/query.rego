package terraform.aws

den y[res] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  after := resource.change.after
  # Detect insecure authentication_type
  after.authentication_type == "NONE"
  res := {
    "msg": sprintf("IoT domain configuration '%s' has authentication_type set to NONE, enabling unauthenticated access", [resource.address]),
    "resource": resource.address
  }
}
