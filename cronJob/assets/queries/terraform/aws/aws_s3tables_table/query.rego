package main

__rego_metadata__ = {
  "id": "AWS023",
  "version": "1.0",
  "title": "S3Tables table should have encryption configuration",
  "description": "Ensure that aws_s3tables_table defines an encryption_configuration to encrypt data at rest.",
  "severity": "HIGH",
  "type": "VIOLATION",
  "service": "s3tables",
  "resource": "aws_s3tables_table"
}

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  resource.change.after.encryption_configuration == null
}