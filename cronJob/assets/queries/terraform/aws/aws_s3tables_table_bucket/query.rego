package main

import data.tfplan as tfplan

deny[msg] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  not resource.change.after.encryption_configuration
  msg := sprintf("Resource '%s' does not have encryption_configuration block", [resource.address])
}