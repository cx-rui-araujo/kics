package main

violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  resource.change.actions[_] != "delete"
  not resource.change.after.encryption_configuration
  issue := {"message": "S3 Tables table should have an encryption_configuration block"}
}

violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table"
  resource.change.actions[_] != "delete"
  enc := resource.change.after.encryption_configuration[_]
  enc.encryption_type != "SSE_KMS"
  issue := {"message": "encryption_configuration.encryption_type should be SSE_KMS"}
}