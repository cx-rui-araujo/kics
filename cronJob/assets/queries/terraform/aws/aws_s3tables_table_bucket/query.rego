package terraform.aws

__rego_metadata__ := {"id": "AWS-S3TABLES-001", "title": "Ensure S3tables table bucket encryption is configured properly", "description": "Check that encryption_configuration is set and uses SSE-KMS", "severity": "HIGH", "type": "Security"}

deny[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  after := resource.change.after
  not after.encryption_configuration
  res := {
    "msg": sprintf("Resource '%v' does not have encryption_configuration set", [resource.address]),
    "resource": resource.address
  }
}

deny[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  ecs := resource.change.after.encryption_configuration[0]
  ecs.encryption_type != "SSE-KMS"
  res := {
    "msg": sprintf("Resource '%v' encryption_configuration uses insecure algorithm '%v'", [resource.address, ecs.encryption_type]),
    "resource": resource.address
  }
}