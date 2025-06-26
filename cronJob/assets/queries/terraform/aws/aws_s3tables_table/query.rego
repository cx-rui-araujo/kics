package main

__rego_metadata__ := {
  "id": "KICS-AWS-S3TABLES-001",
  "title": "aws_s3tables_table should use KMS encryption",
  "severity": "HIGH",
  "type": "terraform",
  "resource_type": "aws_s3tables_table"
}

deny[message] {
  resource := input.resource
  resource.type == "aws_s3tables_table"
  not resource.values.encryption_configuration
  message := sprintf("Resource %s is missing encryption_configuration.", [resource.address])
}

deny[message] {
  resource := input.resource
  resource.type == "aws_s3tables_table"
  enc := resource.values.encryption_configuration[0]
  enc.encryption_type != "KMS"
  message := sprintf("Resource %s uses insecure encryption_type %s.", [resource.address, enc.encryption_type])
}