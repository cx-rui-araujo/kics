package terraform_aws

import data.terraform.tfplan as tfplan

deny[resource] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  after := resource.change.after
  # flag if using default SSE-S3 (AES256) instead of KMS
  after.encryption_configuration != null
  after.encryption_configuration[0].sse_algorithm == "AES256"
}