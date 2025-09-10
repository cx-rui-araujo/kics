package terraform

import fmt

__rego_metadata__ := {"id":"KICS-001","title":"S3Tables Table Bucket encryption missing","severity":"HIGH","type":"VULNERABILITY"}

violation[{"msg":msg,"resource":resource.address,"metadata":__rego_metadata__}] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3tables_table_bucket"
  not resource.change.after.encryption_configuration
  msg := fmt.sprintf("Resource %s does not specify encryption_configuration, defaulting to unencrypted storage", [resource.address])
}