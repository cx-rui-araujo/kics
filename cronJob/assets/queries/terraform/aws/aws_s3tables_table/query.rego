package terraform.aws_s3tables_table.EncryptionConfiguration

__rego_metadata__ := {
  "id": "KICS-AWS-S3TABLES-001",
  "title": "S3Tables table should define encryption_configuration",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

violation[{
  "msg": msg,
  "resource": address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after
  # Detect missing or empty encryption_configuration
  not after.encryption_configuration
  address := resource.address
  msg := sprintf("Resource '%s' does not define encryption_configuration, which may leave data unencrypted.", [address])
}