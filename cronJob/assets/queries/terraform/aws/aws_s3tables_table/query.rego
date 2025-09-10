package aws

__rego_metadata__ = {
  "id": "KICS-AWS-001",
  "title": "S3 tables should have encryption configuration",
  "severity": "HIGH",
}

violation[{
  "msg": msg,
  "resource": address,
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  not resource.change.after.encryption_configuration
  msg := sprintf("S3 table %s does not have encryption configured", [resource.address])
  address := resource.address
}