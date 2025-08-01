package terraform.aws.S3Tables.Encryption

__rego_metadata__ := {
  "id": "KICS-TF-AWS-001",
  "title": "Ensure S3Tables tables use SSE-KMS",
  "description": "S3Tables table encryption_configuration should specify SSE-KMS",
  "severity": "HIGH",
  "type": "VIOLATION",
  "platform": "Terraform"
}

violation[issue] {
  resource := input.resource_configurations["aws_s3tables_table"][_]
  enc := resource.encryption_configuration
  enc.encryption_type == "SSE-S3"
  issue := {
    "resource": resource.address,
    "message": sprintf("S3Tables table '%s' is using SSE-S3 encryption. It should use SSE-KMS.", [resource.address])
  }
}