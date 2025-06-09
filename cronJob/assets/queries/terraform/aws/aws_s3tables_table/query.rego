package kics

__rego_metadata__ := {
  "id": "AWS-S3TABLE-1",
  "title": "S3 Table without encryption",
  "description": "Ensure aws_s3tables_table has encryption_configuration set to encrypt data at rest",
  "severity": "HIGH",
  "type": "VIOLATION"
}

violation[{
  "resource": resource.address,
  "msg": msg,
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
  msg := sprintf("Resource '%s' does not have encryption_configuration set", [resource.address])
}