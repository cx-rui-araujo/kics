package tfplan

violation[{"id": id, "message": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after
  not after.encryption_configuration
  id := resource.address
  msg := "Missing encryption_configuration: S3Tables table should enforce KMS encryption to protect data at rest."
}