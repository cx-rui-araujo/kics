package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  enc := resource.change.after.encryption_configuration
  enc.encryption_option == "NONE"
  msg := sprintf("aws_s3tables_table '%s' has encryption disabled (encryption_option set to 'NONE').", [resource.address])
}