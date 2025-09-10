package main

# Ensure aws_cloudwatch_event_connection specifies a KMS key for encryption
template_title := "Ensure aws_cloudwatch_event_connection has a kms_key_identifier"
template_id := "INSECURE_AWS_CLOUDWATCH_EVENT_CONNECTION_NO_KMS"

deny[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  not resource.change.after.kms_key_identifier
  violation := {
    "msg": sprintf("Resource '%s' does not specify a kms_key_identifier; event connections should be encrypted using a KMS key.", [resource.address]),
    "metadata": {
      "id": template_id,
      "title": template_title,
      "severity": "HIGH",
      "category": "encryption",
      "platform": "Terraform"
    }
  }
}