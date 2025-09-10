package main

__rego_metadata__ = {
  "id": "KICS-0001",
  "title": "Using AWS-managed KMS key in CloudWatch Event Connection",
  "severity": "LOW",
  "type": "VULNERABILITY"
}

violation[resource] {
  resource := data.terraform.configuration.root_module.resources[_]
  resource.type == "aws_cloudwatch_event_connection"
  val := resource.values.kms_key_identifier
  startswith(val, "alias/aws/")
}
