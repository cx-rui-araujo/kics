package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  after := resource.change.after
  enc := after.encryption_configuration
  enc != null
  rules := enc.server_side_encryption_configuration.rules
  some i
  rule := rules[i]
  rule.apply_server_side_encryption_by_default.sse_algorithm == "AES256"
  msg := "Weak encryption algorithm used: AES256. Use aws:kms instead."
}