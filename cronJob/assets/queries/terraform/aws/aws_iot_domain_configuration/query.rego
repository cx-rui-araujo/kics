package main

__rego_metadata__ = {
  "id": "AWS_IOT_001",
  "title": "AWS IoT Domain Configuration using insecure authentication type",
  "severity": "MEDIUM",
  "type": "misconfiguration",
  "uri": "https://docs.kics.io/latest/queries/aws/iot/authentication_type_not_certificate"
}

violation[{
  "msg": msg
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_iot_domain_configuration"
  after := resource.change.after
  after.authentication_type == "AMAZON_COGNITO_USER_POOLS"
  msg := sprintf("IoT Domain Configuration '%s' uses AMAZON_COGNITO_USER_POOLS instead of certificate-based authentication.", [after.domain_name])
}