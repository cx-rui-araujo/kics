package terraform.aws

__rego_meta__ := {
  "title": "S3Tables bucket without KMS encryption",
  "description": "Detects aws_s3tables_table_bucket resources that do not use a customer-managed KMS key for encryption.",
  "severity": "MEDIUM"
}

default deny = false

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  after := resource.change.after
  enc := after.encryption_configuration
  enc == null
}