package main

__rego_metadata__ = {
  "id": "KICS-0001",
  "title": "Ensure S3Tables table encryption_configuration is enabled",
  "severity": "HIGH",
  "type": "AWS",
  "category": "Encryption at Rest"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
  msg = sprintf("S3Tables table '%s' must have encryption_configuration enabled", [resource.address])
}