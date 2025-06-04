package terraform.aws_s3tables_table

__rego_meta__ = {
  "id": "KICS-42424",
  "title": "Ensure aws_s3tables_table uses SSE-KMS encryption",
  "severity": "HIGH",
  "type": "VIOLATION",
  "category": "Encryption Configuration"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after
  not after.encryption_configuration
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  enc := resource.change.after.encryption_configuration[0]
  enc.encryption_option != "SSE_KMS"
}