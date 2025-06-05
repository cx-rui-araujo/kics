package main

__rego_metadata__ := {
  "id": "KICS-999",
  "title": "Ensure custom KMS key is used for CloudWatch Event Connection",
  "description": "Using the default AWS-managed KMS key for CloudWatch Event Connection may not meet security requirements. A customer-managed key should be used.",
  "severity": "MEDIUM",
  "category": "Encryption",
}

violation[resource] {
  resource := tfconfig.resource.aws_cloudwatch_event_connection[_]
  kms := resource.values.kms_key_identifier
  startswith(kms, "alias/aws")
}