package main

deny[msg] {
  input.resource_type == "aws_s3tables_table_bucket"
  enc := input.resource_values.encryption_configuration[0].rule[0].apply_server_side_encryption_by_default[0]
  enc.sse_algorithm != "aws:kms"
  msg = "S3Tables bucket encryption is not using AWS KMS (aws:kms). Use AWS KMS for stronger encryption."
}