package aws_iot

__rego_metadata__ := { 
  \"id\": \"KICS-0001\",\n  \"title\": \"Ensure AWS IoT Domain Configuration uses secure protocols and authentication\",\n  \"severity\": \"HIGH\",\n  \"type\": \"VULNERABILITY\"\n}

violation[violation] {
  resource := input.resource_changes[_]
  resource.type == \"aws_iot_domain_configuration\"
  after := resource.change.after
  after.application_protocol != \"MqttTls\"
  violation = {
    \"msg\": sprintf(\"Insecure application_protocol '%v', must be 'MqttTls'\", [after.application_protocol]),
    \"resource\": resource.address
  }
}

violation[violation] {
  resource := input.resource_changes[_]
  resource.type == \"aws_iot_domain_configuration\"
  after := resource.change.after
  after.authentication_type != \"TLS\"
  violation = {
    \"msg\": sprintf(\"Insecure authentication_type '%v', must be 'TLS'\", [after.authentication_type]),
    \"resource\": resource.address
  }
}
