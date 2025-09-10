package resources

__rego_metadata__ := {
  "id": "AWS_S3TABLES_TABLE_ENCRYPTION_MISSING",
  "version": "1.0",
  "title": "Ensure S3Tables tables have encryption configuration",
  "description": "S3Tables tables should use encryption_configuration to protect data at rest.",
  "severity": "HIGH",
  "impact": "Data at rest in the table may not be encrypted",
  "resolution": "Add encryption_configuration block with appropriate encryption_option",
  "provider": "aws",
  "service": "s3tables",
  "reference_id": "CUSTOM_AWS_S3TABLES_ENCRYPTION"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
  resource
}