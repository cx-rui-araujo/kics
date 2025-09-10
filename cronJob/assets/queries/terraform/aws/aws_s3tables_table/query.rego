package kics

import data

__rego_meta__ = {
  "id": "AWS_S3TABLES_ENCRYPTION_NOT_SPECIFIED",
  "title": "Ensure S3tables table has strong encryption configured",
  "severity": "HIGH",
  "description": "S3tables tables should define an encryption_configuration block using SSE-KMS to protect data at rest.",
  "recommended_actions": ["Add encryption_configuration with encryption_type = \"SSE-KMS\" and specify a KMS key"]
}

deny[resource] {
  resource := input.resource.aws_s3tables_table[_]
  not resource.encryption_configuration
}

deny[resource] {
  resource := input.resource.aws_s3tables_table[_]
  enc := resource.encryption_configuration[0]
  enc.encryption_type != "SSE-KMS"
}