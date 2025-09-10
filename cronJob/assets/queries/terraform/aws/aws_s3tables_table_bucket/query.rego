package terraform

import data.tfplan as tfplan

__rego_metadata__ := {"id":"KICS-AWS-ENCRYPTION-001","title":"Ensure aws_s3tables_table_bucket has encryption_configuration","severity":"HIGH","type":"VULNERABILITY","category":"Encryption at Rest"}

violation[output] {
  resource := tfplan.resource_changes["aws_s3tables_table_bucket"][name]
  resource.change.after.encryption_configuration == null
  output := {"resource": resource.address, "details": "Missing encryption_configuration; data at rest is not encrypted."}
}