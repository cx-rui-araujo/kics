package terraform.security.aws.EnforceS3TablesEncryption

import data.tfconfig

violation[resource] {
  resource := tfconfig.resource.aws_s3tables_table_bucket[_]
  not resource.values.encryption_configuration
  resource
}