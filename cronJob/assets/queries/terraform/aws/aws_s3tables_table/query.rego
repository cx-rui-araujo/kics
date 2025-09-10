package KICS.AWS.S3Tables

__rego_metadata__ = {
  "id": "KICS-NEW-0001",
  "title": "Ensure S3Tables tables have encryption enabled",
  "severity": "MEDIUM",
  "related_guidelines": []
}

deny[{
  "msg": msg,
  "resource": resource_name
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after
  not after.encryption_configuration
  resource_name := resource.address
  msg := sprintf("Resource %s does not have encryption_configuration set", [resource_name])
}