package main

metadata = {
  "id": "AWS_S3TABLES_ENC_001",
  "version": "1.0.0",
  "name": "Ensure S3Tables table uses KMS encryption",
  "description": "Detects aws_s3tables_table resources that do not use SSE_KMS encryption or lack encryption_configuration.",
  "severity": "HIGH",
  "recommended_actions": ["Configure encryption_configuration with encryption_type = \"SSE_KMS\" and a valid kms_master_key_id."],
  "references": ["https://docs.hashicorp.com/terraform/providers/aws/r/s3tables_table#encryption_configuration"]
}

deny[issue] {
  input.resource_changes[_] = rc
  rc.type == "aws_s3tables_table"
  after := rc.change.after
  # block missing entirely
  not after.encryption_configuration
  issue := {
    "msg": "aws_s3tables_table resource is missing encryption_configuration block",
    "resource": rc.address
  }
}

deny[issue] {
  input.resource_changes[_] = rc
  rc.type == "aws_s3tables_table"
  after := rc.change.after.encryption_configuration[0]
  # wrong encryption type
  after.encryption_type != "SSE_KMS"
  issue := {
    "msg": sprintf("aws_s3tables_table uses unsupported encryption type '%v'", [after.encryption_type]),
    "resource": rc.address
  }
}