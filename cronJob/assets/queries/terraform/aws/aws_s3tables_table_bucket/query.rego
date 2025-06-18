package main

deny[alert] {
  resource := resource_blocks.aws_s3tables_table_bucket[_]
  # Catch use of weak AES256 instead of stronger KMS encryption
  enc := resource.attributes.encryption_configuration.default_server_side_encryption_configuration[0].sse_algorithm
  enc.value == "AES256"
  alert := {
    msg: sprintf("Resource '%s' uses insecure AES256 encryption algorithm", [resource.address]),
    resource: resource.address,
    severity: "MEDIUM",
  }
}