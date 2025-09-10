package terraform.security

# Deny aws_s3tables_table resources without an encryption_configuration block
violation[{
  "id": "AWS_S3TABLES_ENCRYPTION_MISSING",
  "message": sprintf("S3Tables table '%s' does not have an encryption_configuration block and is unencrypted.", [rc.address]),
  "severity": "HIGH"
}] {
  rc := input.plan.resource_changes[_]
  rc.type == "aws_s3tables_table"
  rc.change.after != null
  not rc.change.after.encryption_configuration
}