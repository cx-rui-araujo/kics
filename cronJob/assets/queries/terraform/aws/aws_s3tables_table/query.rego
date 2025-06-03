package kics.aws_s3tables_table

__rego_metadata__ = {"id":"KICS-TF-ENCRYPT-001","title":"Ensure aws_s3tables_table has encryption_configuration set","severity":"HIGH","type":"VULNERABILITY","description":"S3Tables table missing encryption_configuration or using insecure algorithm.","recommendation":"Add encryption_configuration block with a secure SSE algorithm and valid kms_master_key_id."}

deny[message] {
  input.Type == "aws_s3tables_table"
  not input.Values.encryption_configuration
  message := sprintf("Resource '%s' missing encryption_configuration", [input.ResourceName])
}

deny[message] {
  input.Type == "aws_s3tables_table"
  enc := input.Values.encryption_configuration
  enc.sse_algorithm == "NONE"
  message := sprintf("Resource '%s' uses insecure encryption algorithm 'NONE'", [input.ResourceName])
}