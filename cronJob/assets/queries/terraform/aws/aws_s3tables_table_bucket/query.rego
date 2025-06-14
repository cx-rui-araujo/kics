package main

__rego_metadata__ = {
  "id": "AWS162",
  "title": "Ensure S3 Tables Table Bucket encryption at rest",
  "severity": "HIGH",
  "type": "terraform",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  not resource.change.after.encryption_configuration
}