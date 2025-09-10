package aws.s3tables

__rego_metadata__ := {
  "id": "AWS_S3TABLES_001",
  "title": "Ensure aws_s3tables_table uses encryption_configuration",
  "severity": "HIGH",
  "category": "Encryption",
  "description": "Checks that aws_s3tables_table resources have encryption_configuration defined with AWS KMS.",
}

den[res] {
  input.resource == "aws_s3tables_table"
  instance := input.instances[_]
  # Check if encryption_configuration block is missing
  not instance.attributes.encryption_configuration
  res := {
    "message": "Missing encryption_configuration, data at rest may not be encrypted",
    "resource_id": instance.id
  }
}

den[res] {
  input.resource == "aws_s3tables_table"
  instance := input.instances[_]
  # Check if SSE algorithm is not aws:kms
  enc := instance.attributes.encryption_configuration[0]
  enc.sse_algorithm != "aws:kms"
  res := {
    "message": "encryption_configuration.sse_algorithm should be aws:kms",
    "resource_id": instance.id
  }
}