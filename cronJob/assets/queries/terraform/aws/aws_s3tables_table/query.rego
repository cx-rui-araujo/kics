package terraform.kics

__rego_metadata__ := {"id":"AWS_S3TABLE_ENC_001","title":"Ensure S3Tables tables have encryption_configuration","severity":"HIGH","type":"DATA_SECURITY","category":"encryption"}

deny[msg] {
  resource := tfplan.resource_changes["aws_s3tables_table"][_].change.after
  not resource.encryption_configuration
  msg := sprintf("Resource '%s' missing encryption_configuration", [resource.name])
}

deny[msg] {
  resource := tfplan.resource_changes["aws_s3tables_table"][_].change.after
  resource.encryption_configuration
  alg := resource.encryption_configuration[0].rule.sse_algorithm
  alg != "aws:kms"
  msg := sprintf("Resource '%s' uses weak encryption '%s'", [resource.name, alg])
}