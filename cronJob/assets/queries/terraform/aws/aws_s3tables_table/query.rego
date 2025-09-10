package main

import data.tfplan as tfplan

deny[msg] {
  rc := tfplan.resource_changes[_]
  rc.type == "aws_s3tables_table"
  not rc.change.after.encryption_configuration
  msg := "Resource aws_s3tables_table missing encryption_configuration: data at rest will be unencrypted"
}