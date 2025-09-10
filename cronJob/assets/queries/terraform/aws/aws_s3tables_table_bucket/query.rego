package terraform.kics

__metadata__ := {
  "id": "CUSTOM_AWS_001",
  "target": "aws_s3tables_table_bucket",
  "severity": "MEDIUM",
  "type": "Vulnerability",
  "title": "S3 tables bucket encryption should use AWS KMS"
}

violation[msg] {
  res := input.resource[_]
  res.Type == "aws_s3tables_table_bucket"
  not res.Values.encryption_configuration
  msg := sprintf("Resource '%s' does not have encryption_configuration", [res.Name])
}

violation[msg] {
  res := input.resource[_]
  res.Type == "aws_s3tables_table_bucket"
  enc := res.Values.encryption_configuration[0]
  enc.sse_algorithm != "aws:kms"
  msg := sprintf("Resource '%s' encryption_algorithm '%s' is not aws:kms", [res.Name, enc.sse_algorithm])
}