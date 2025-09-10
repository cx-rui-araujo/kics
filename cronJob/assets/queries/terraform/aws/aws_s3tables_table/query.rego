package terraform.aws.S3TablesTable

import data.terraform

violation[issue] {
  resource := terraform.resource["aws_s3tables_table"][name]
  not resource.block.encryption_configuration
  issue := {
    "rule_id": "AWS_S3_TABLE_MISSING_ENCRYPTION",
    "message": "S3 table should have encryption_configuration block to enforce SSE encryption",
    "severity": "HIGH",
    "resource": name
  }
}