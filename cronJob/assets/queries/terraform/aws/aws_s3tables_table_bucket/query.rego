package terraform.aws_s3tables

deny[msg] {
  resource := input.root_module.resources[_]
  resource.type == "aws_s3tables_table_bucket"
  enc := resource.values.encryption_configuration
  enc.sse_algorithm != "aws:kms"
  msg := sprintf("Resource '%s' uses insecure SSE algorithm '%s'; should use aws:kms.", [resource.address, enc.sse_algorithm])
}