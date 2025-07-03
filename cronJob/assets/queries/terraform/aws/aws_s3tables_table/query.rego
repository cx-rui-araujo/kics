package main

__rego_metadata__ := {
  "id": "KICS_CUSTOM_001",
  "title": "S3Tables Table without encryption configuration",
  "severity": "HIGH",
  "type": "VIOLATION",
  "description": "Detect aws_s3tables_table resources missing encryption_configuration leading to unencrypted data at rest."
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
  res := {
    "resource": resource.address,
    "message": "aws_s3tables_table resource does not define encryption_configuration, risking unencrypted data at rest"
  }
}