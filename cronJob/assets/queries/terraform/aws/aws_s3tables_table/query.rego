package terraform.aws_s3tables_table

__rego_metadata__ := {
  "id": "KICS-9999",
  "title": "S3Tables table uses weak or no encryption_configuration",
  "severity": "HIGH",
  "type": "Terraform Security Check",
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after

  # encryption_configuration block missing or using weak AES256 algorithm
  (not after.encryption_configuration) || (after.encryption_configuration[0].sse_s3_encryption == "AES256")

  res := {
    "message": sprintf("Resource '%s' has missing or weak encryption_configuration; using default AES256 or unencrypted data at rest.", [resource.address]),
    "resource": resource.address
  }
}