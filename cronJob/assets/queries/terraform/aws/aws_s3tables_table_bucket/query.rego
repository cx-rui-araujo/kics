package terraform.kics

__rego_metadata__ := {
  "id": "AWS_TF_S3TABLES_1",
  "title": "Ensure aws_s3tables_table_bucket uses server-side encryption",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

violation[resp] {
  resource := input.resource_changes[_]
  resource.resource_type == "aws_s3tables_table_bucket"
  after := resource.change.after

  # Fail if encryption_configuration is missing
  not after.encryption_configuration
  resp := {
    "resource": resource.address,
    "message": sprintf("S3Tables table bucket '%s' should define encryption_configuration for server-side encryption", [resource.address])
  }
}

violation[resp] {
  resource := input.resource_changes[_]
  resource.resource_type == "aws_s3tables_table_bucket"
  after := resource.change.after
  ec := after.encryption_configuration

  # Fail if SSE algorithm is not one of the accepted values
  some i
  alg := ec[i].sse_algorithm
  not alg in ["AES256", "aws:kms"]
  resp := {
    "resource": resource.address,
    "message": sprintf("Invalid sse_algorithm '%s' for encryption_configuration on %s, must be AES256 or aws:kms", [alg, resource.address])
  }
}