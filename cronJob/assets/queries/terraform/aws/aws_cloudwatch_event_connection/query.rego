package main

__rego_metadata__ = {
  "id": "AWS050",
  "version": "1.0.0",
  "title": "Avoid using AWS-managed KMS keys for EventBridge connections",
  "description": "Using AWS-managed KMS keys (alias/aws/*) may not comply with security best practices.",
  "severity": "LOW",
  "related_links": ["https://docs.kics.io/latest/queries/aws/"]
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  key := resource.change.after.kms_key_identifier
  startswith(key, "alias/aws/")
}