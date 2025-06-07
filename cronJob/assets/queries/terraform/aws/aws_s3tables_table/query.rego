package query

__rego_metadata__ := {
  "id": "KICS_AWS_S3TABLES_ENCRYPTION_1",
  "title": "Ensure aws_s3tables_table resources have encryption_configuration",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "supported_resources": ["aws_s3tables_table"]
}

deny[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after
  not after.encryption_configuration
  message := sprintf("Resource '%s' does not define encryption_configuration, leaving data unencrypted.", [resource.address])
}