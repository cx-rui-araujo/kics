package terraform_scanner

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
  msg = "aws_s3tables_table resource missing encryption_configuration; data at rest will be unencrypted."
}