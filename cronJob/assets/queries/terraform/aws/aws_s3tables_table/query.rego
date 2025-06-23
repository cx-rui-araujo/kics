package kics

default deny = false

__rego_metadata__ = {
  "id": "KICS-AWS-ENCRYPTION-001",
  "title": "S3Tables table should have encryption_configuration",
  "severity": "HIGH",
}

deny[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after
  not after.encryption_configuration
  violation := {
    "message": sprintf("Resource '%s' should define encryption_configuration to ensure at-rest encryption.", [resource.address]),
    "resource": resource.address,
  }
}