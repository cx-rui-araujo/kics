package kics

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
}