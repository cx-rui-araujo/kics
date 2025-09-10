package kics

__rego_metadata__ = {
  "id": "KICS-001",
  "title": "Terraform aws_ec2_network_insights_path filter_at_source.source_address not specified",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "description": "A Network Insights Path filter_at_source without a specified source_address allows unfiltered traffic from any source, potentially exposing internal networks.",
}

deny[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  after := resource.change.after
  filter_src := after.filter_at_source
  filter_src != null
  not filter_src.source_address
  issue := {
    "message": sprintf("Resource '%s' defines filter_at_source but no source_address, allowing unrestricted sources.", [resource.address]),
    "resource": resource.address
  }
}