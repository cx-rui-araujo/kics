package main

__rego_metadata__ = {
  "id": "KICS-AWS-42356",
  "title": "Ensure aws_s3tables_table_bucket enforces encryption_configuration",
  "severity": "HIGH",
  "description": "The aws_s3tables_table_bucket resource must define encryption_configuration to ensure data at rest is encrypted.",
  "recommended_actions": ["Add an encryption_configuration block with the desired SSE-KMS settings."]
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  not resource.change.after.encryption_configuration
}