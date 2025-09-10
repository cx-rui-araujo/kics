package main

import data.terraform as tf

deny[msg] {
  resource := tf.resource["aws_s3tables_table_bucket"][_]
  not resource.values.encryption_configuration
  msg = "Missing encryption_configuration in aws_s3tables_table_bucket: data at rest is not encrypted"
}

deny[msg] {
  resource := tf.resource["aws_s3tables_table_bucket"][_]
  algo := resource.values.encryption_configuration[0].server_side_encryption_configuration[0].rule[0].apply_server_side_encryption_by_default[0].sse_algorithm
  algo == "AES256"
  msg = sprintf("S3 table bucket uses insecure encryption algorithm: %v", [algo])
}