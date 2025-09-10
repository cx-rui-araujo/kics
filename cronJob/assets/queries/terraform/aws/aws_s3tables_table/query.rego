package main

__rego_metadata__ := {"id":"KICS-aws-s3tables-encryption","title":"Ensure aws_s3tables_table has encryption_configuration with SSE-KMS","severity":"HIGH","service":"s3tables"}

deny[resp] {
  rc := input.resource_changes[_]
  rc.type == "aws_s3tables_table"
  not rc.change.after.encryption_configuration
  resp := {"message":"Missing encryption_configuration block on aws_s3tables_table"}
}

deny[resp] {
  rc := input.resource_changes[_]
  rc.type == "aws_s3tables_table"
  enc := rc.change.after.encryption_configuration
  enc.encryption_type != "SSE_KMS"
  resp := {"message":sprintf("aws_s3tables_table uses insecure encryption: %v", [enc.encryption_type])}
}