package terraform.aws_s3tables_table_bucket

deny[resource] {
  resource := tfconfig.resource_blocks["aws_s3tables_table_bucket"][name]
  enc_blocks := resource.block.child_blocks["encryption_configuration"]
  enc_blocks
  enc_type := enc_blocks[0].block.attribute["encryption_type"].value
  enc_type != "SSE-KMS"
}