package terraform.aws.s3tables

deny[{
  msg: msg,
  resource: resource_address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  resource_address := resource.address
  // Check if encryption_configuration is missing or empty
  not resource.change.after.encryption_configuration
  msg := sprintf("Resource '%s' is missing 'encryption_configuration'. Data at rest encryption is not enabled.", [resource_address])
}