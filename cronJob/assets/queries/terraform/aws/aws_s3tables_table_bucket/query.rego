package terraform.aws.s3tables

import data.terraform.tfplan as tfplan

# Ensure aws_s3tables_table_bucket has server-side encryption configured
violation[{
  "msg": msg,
  "resource": res.address
}] {
  res := tfplan.resource_changes[_]
  res.type == "aws_s3tables_table_bucket"
  not res.change.after.encryption_configuration
  msg := sprintf("Resource '%s' is missing encryption_configuration; data at rest may be unencrypted.", [res.address])
}