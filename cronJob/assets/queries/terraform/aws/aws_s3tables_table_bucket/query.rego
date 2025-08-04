package terraform.aws_security

import data.terraform.plan as plan

__rego_metadata__ = {
  "id": "KICS-0001",
  "title": "Ensure aws_s3tables_table_bucket has server-side encryption",
  "severity": "HIGH",
  "type": "terraform",
  "confidence": "HIGH",
}

violation[res] {
  res := plan.resource_changes[_]
  res.type == "aws_s3tables_table_bucket"
  not res.change.after.encryption_configuration
}