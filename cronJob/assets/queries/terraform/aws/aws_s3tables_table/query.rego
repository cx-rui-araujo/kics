package main

import data

__rego_metadata__ := {
  "id": "AWS_S3TABLES_ENCRYPTION_MISSING",
  "title": "Ensure aws_s3tables_table resources have encryption configuration",
  "severity": "HIGH",
  "type": "misconfiguration"
}

violation[resource] {
  resource := data.terraform.resources.aws_s3tables_table[_]
  resource.encryption_configuration == null
}