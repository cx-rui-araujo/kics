package kics

violation[output] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  after := resource.change.after
  enc := after.encryption_configuration
  enc.sse_algorithm != "aws:kms"
  output := {
    "message": sprintf("Weak S3 bucket encryption algorithm %v, expected aws:kms", [enc.sse_algorithm])
  }
}
