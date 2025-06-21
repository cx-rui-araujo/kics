id: "AWS_S3TABLES_TABLE_BUCKET_ENCRYPTION"
category: "Encryption"
version: "1.0"
severity: "HIGH"
metadata:
  description: "Ensure aws_s3tables_table_bucket has server-side encryption enabled"
  recommended_action: "Add encryption_configuration with SSE_KMS algorithm"
  link: "https://docs.kics.io/latest/creating-queries/"
query: |
  package main

  violation[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3tables_table_bucket"
    not resource.change.after.encryption_configuration
  }