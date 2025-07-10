package terraform_aws_s3tables

import data.tfconfig

deny[msg] {
  res := tfconfig.resource.aws_s3tables_table_bucket[_]
  not res.encryption_configuration
  msg = sprintf("Resource '%s' does not set encryption_configuration, data at rest is unencrypted.", [res.address])
}

deny[msg] {
  res := tfconfig.resource.aws_s3tables_table_bucket[_]
  enc := res.encryption_configuration
  enc.encryption_type != "KMS"
  msg = sprintf("Resource '%s' uses insecure encryption_type '%s'; must use KMS.", [res.address, enc.encryption_type])
}