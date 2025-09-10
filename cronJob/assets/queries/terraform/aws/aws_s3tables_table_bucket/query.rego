package main

__rego_metadata__ = {
  "id": "KICS-9999",
  "title": "S3Tables bucket insecure encryption algorithm",
  "severity": "HIGH",
  "type": "VIOLATION",
  "description": "Detect buckets using RSA1024 which is considered insecure."
}

denied[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  after := resource.change.after.encryption_configuration
  after.algorithm == "RSA1024"
  message := sprintf("Resource '%s' uses insecure encryption algorithm 'RSA1024'", [resource.address])
}