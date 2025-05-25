# S3tables Table Bucket encryption_configuration must be defined and use AWS KMS
package terraform.aws_s3tables

denial[violation] {
  resource := input.resource_changes.aws_s3tables_table_bucket[_]
  after := resource.change.after
  # encryption_configuration is missing
  not after.encryption_configuration
  violation := {
    "msg": sprintf("Resource %s does not have encryption_configuration. Data at rest may be unencrypted.", [resource.address]),
    "resource": resource.address
  }
}

# Ensure using SSE-KMS algorithm

denial[violation] {
  resource := input.resource_changes.aws_s3tables_table_bucket[_]
  enc := resource.change.after.encryption_configuration[0]
  alg := enc.server_side_encryption_by_default.sse_algorithm
  # algorithm is not aws:kms
  alg != "aws:kms"
  violation := {
    "msg": sprintf("Resource %s uses weak encryption algorithm %s. Expected aws:kms.", [resource.address, alg]),
    "resource": resource.address
  }
}