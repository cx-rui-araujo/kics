package aws

__rego_meta__ = {"id": "AWS_S3TABLES_ENCRYPTION_MISSING", "title": "S3 Table should have encryption_configuration enabled", "severity": "HIGH", "type": "VIOLATION"}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
  resource_address := resource.address
  message := sprintf("Resource '%s' has no encryption_configuration; data at rest is not encrypted", [resource_address])
  resource := {"address": resource_address, "message": message}
}