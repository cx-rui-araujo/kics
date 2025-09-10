package kics

import data.terraform as tf

__rego_metadata__ := {
  "id": "KICS-9999",
  "title": "S3Tables Table Bucket should use KMS encryption",
  "severity": "HIGH",
  "description": "Checks that aws_s3tables_table_bucket resources use aws:kms for server-side encryption.",
  "platform": "Terraform",
  "affected_resource": "aws_s3tables_table_bucket"
}

deny[msg] {
  resource := tf.resource_blocks[_]
  resource.type == "aws_s3tables_table_bucket"
  enc := resource.attributes.encryption_configuration
  enc != null
  alg := enc[0].server_side_encryption_configuration[0].apply_server_side_encryption_by_default[0].sse_algorithm
  alg != "aws:kms"
  msg := sprintf("Resource '%s' uses weak SSE algorithm '%s'; must be aws:kms", [resource.labels[0], alg])
}