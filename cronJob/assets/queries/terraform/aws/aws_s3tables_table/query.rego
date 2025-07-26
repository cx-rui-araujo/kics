package terraform.aws

import data.terraform.tfconfig as tfconfig

# Ensure aws_s3tables_table resources define encryption_configuration
violation[resource] {
  resource := tfconfig.resource["aws_s3tables_table"][name]
  not resource.block.encryption_configuration
}