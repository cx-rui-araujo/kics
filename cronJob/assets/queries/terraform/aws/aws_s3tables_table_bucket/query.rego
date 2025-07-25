package main

import tfplan/v2 as tfplan

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "Ensure aws_s3tables_table_bucket has encryption_configuration set",
  "severity": "HIGH",
  "type": "MISC_SECURITY"
}

denied[resource] {
  resource := tfplan.resource_changes[resource_id]
  resource.type == "aws_s3tables_table_bucket"
  not resource.change.after.encryption_configuration
}