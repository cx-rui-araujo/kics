package main

__rego_metadata__ := {
  "id": "KICS_TF_AWS_0001",
  "title": "Avoid using default AWS KMS key for CloudWatch Event Connection",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "short_description": "Using the AWS managed default KMS key (alias/aws/...) may allow AWS administrators to decrypt connection credentials."
}

denied[violation] {
  input.block.type == "resource"
  input.block.labels[0] == "aws_cloudwatch_event_connection"
  kms := input.block.attributes.kms_key_identifier.value
  startswith(kms, "alias/aws/")
  violation := {
    "message": sprintf("CloudWatch Event Connection uses default KMS key: %s", [kms]),
    "metadata": __rego_metadata__,
    "start_line": input.block.attributes.kms_key_identifier.start_line,
    "end_line": input.block.attributes.kms_key_identifier.end_line
  }
}