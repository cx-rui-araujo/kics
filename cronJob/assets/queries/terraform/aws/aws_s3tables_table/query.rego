package main

# KICS query to ensure aws_s3tables_table has encryption_configuration
# More info: https://docs.kics.io/latest/creating-queries/

deny[message] {
  # iterate over all resource changes
  resource := input.resource_changes[_]
  # select aws_s3tables_table resources
  resource.type == "aws_s3tables_table"
  # if encryption_configuration is missing or empty, raise an issue
  not resource.change.after.encryption_configuration
  message := sprintf("S3Tables table '%s' does not have encryption_configuration defined, which may lead to unencrypted data storage.", [resource.address])
}