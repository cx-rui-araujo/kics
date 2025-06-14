package terraform

__rego_metadata__ := {
  "id": "KICS-0001",
  "supported_resources": ["aws_s3tables_table"],
  "severity": "HIGH",
  "type": "VIOLATION",
  "title": "aws_s3tables_table SSE_KMS must specify a kms_key_arn"
}

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  encryption := resource.change.after.encryption_configuration
  encryption.encryption_type == "SSE_KMS"
  not encryption.kms_key_arn
}