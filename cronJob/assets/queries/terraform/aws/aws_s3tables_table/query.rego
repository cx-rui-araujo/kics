package terraform.aws.s3tables

violation[{"msg": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after
  not after.encryption_configuration
  msg := sprintf("Resource '%s' is missing 'encryption_configuration'. Data at rest may not be encrypted.", [resource.address])
}

violation[{"msg": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after
  encryption := after.encryption_configuration[0]
  encryption.sse_algorithm != "aws:kms"
  msg := sprintf("Resource '%s' uses insecure SSE algorithm '%s'. Use 'aws:kms' for encryption_configuration.", [resource.address, encryption.sse_algorithm])
}