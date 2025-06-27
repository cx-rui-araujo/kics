package kics

# Detects usage of weak AES256 encryption in aws_s3tables_table_bucket
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  enc := resource.after.encryption_configuration
  # Imaginary vulnerability: defaulting to AES256 is considered weak vs KMS
  enc.server_side_encryption_configuration.rules[_].apply_server_side_encryption_by_default.sse_algorithm == "AES256"
}