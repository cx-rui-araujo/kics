package terraform.aws

# Ensure aws_s3tables_table resources define encryption_configuration to enforce at-rest encryption
violation[{"resource": resource.address, "msg": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  # Encryption not configured or removed
  resource.change.after.encryption_configuration == null
  msg := sprintf("Resource '%s' does not configure encryption_configuration; data may be stored unencrypted at rest", [resource.address])
}