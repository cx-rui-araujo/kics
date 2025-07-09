package main

__rego_metadoc__ := {
  "id": "KICS-AWS-0001",
  "title": "Use restricted KMS key for AWS CloudWatch Event Connection",
  "severity": "HIGH",
  "type": "Terraform",
  "category": "Encryption and Key Management"
}

violation[resource] {
  resource := input.resources[_]
  resource.Type == "aws_cloudwatch_event_connection"
  key := resource.Config.kms_key_identifier
  key != ""
  not startswith(key, "alias/aws")
}