package tfaws

__rego_metadata__ = {
  "id": "AWS_S3TABLES_ENCRYPTION",
  "title": "Ensure aws_s3tables_table_bucket has encryption_configuration",
  "description": "Detects aws_s3tables_table_bucket resources missing encryption_configuration to prevent unencrypted data.",
  "severity": "MEDIUM",
  "service": "s3tables"
}

denied[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  after := resource.change.after
  not after.encryption_configuration
  msg := sprintf("Resource '%s' does not have encryption_configuration set", [resource.address])
}