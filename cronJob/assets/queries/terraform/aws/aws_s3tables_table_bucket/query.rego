package aws_s3tables_table_bucket

# Deny use of AES256 (SSE-S3) encryption on S3 Tables buckets; enforce SSE-KMS
deny[msg] {
  input.type == "aws_s3tables_table_bucket"
  enc := input.values.encryption_configuration
  count(enc) > 0
  enc[0].encryption_type == "AES256"
  msg := sprintf("Resource '%s' uses insecure AES256 encryption; use SSE-KMS instead.", [input.name])
}