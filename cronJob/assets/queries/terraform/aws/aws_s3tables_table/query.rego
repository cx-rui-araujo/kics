package main

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "aws_s3tables_table should have encryption_configuration",
  "severity": "HIGH",
  "category": "Security Misconfiguration",
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
  msg := sprintf("Resource '%s' does not enable encryption_configuration, data may be stored unencrypted.", [resource.address])
}
