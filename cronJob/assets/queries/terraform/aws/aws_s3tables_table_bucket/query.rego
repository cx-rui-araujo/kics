package kics

import data.terraform.tf as tf

__kics__ := {
  "id": "AWS001",
  "title": "Unencrypted S3 Table Bucket",
  "severity": "HIGH",
  "category": "Encryption"
}

deny[msg] {
  resource := tf.resource_blocks[_]
  resource.type == "aws_s3tables_table_bucket"
  not resource.attributes.encryption_configuration
  msg := sprintf("Resource '%v' does not define encryption_configuration, leaving data unencrypted.",[resource.name])
}