package main

__rego_metadata__ := {
  "id": "KICS_AWS_S3TABLES_TABLE_ENCRYPTION_MISSING",
  "title": "AWS S3Tables table should have an encryption_configuration set",
  "severity": "HIGH",
  "type": "terraform",
  "related_resources": ["aws_s3tables_table"]
}

violation[resource] {
  resource := input.blocks[_]
  resource.type == "resource"
  resource.labels[0] == "aws_s3tables_table"
  not resource.body.attributes["encryption_configuration"]
}