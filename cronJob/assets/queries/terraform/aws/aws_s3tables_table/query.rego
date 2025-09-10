package kics

__rego_metadata__ := {
  "id": "S3TABLES_ENCRYPTION_CONFIGURATION",
  "title": "Ensure aws_s3tables_table has encryption_configuration defined",
  "severity": "HIGH",
  "type": "Terraform Security Check",
}

deny[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
  message := sprintf("Resource '%v' does not define encryption_configuration, which may lead to unencrypted data storage", [resource.address])
}