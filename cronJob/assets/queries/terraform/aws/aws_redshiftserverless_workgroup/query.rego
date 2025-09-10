package tfplan

metadata = {
  "id": "CUSTOM_AWS_REDSHIFT_UNSAFE_TRACK_NAME",
  "version": "1.0.0",
  "title": "Do not use insecure track_name values",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "description": "Setting track_name to 'public_read' can expose detailed usage data publicly.",
  "reference_id": "CUST-002"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_redshiftserverless_workgroup"
  after := resource.change.after
  after.track_name == "public_read"
  msg := sprintf("Resource '%v' uses insecure track_name '%v' which can leak sensitive usage data.", [resource.address, after.track_name])
}