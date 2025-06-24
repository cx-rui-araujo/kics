package terraform.AWS.NetworkInsights

__rego_metadata__ := {
  "id": "KICS-AWS-001",
  "title": "AWS Network Insights Path missing source_address filter",
  "description": "Missing filter_at_source.source_address can lead to analyzing from any source address, potentially exposing network paths.",
  "severity": "HIGH"
}

deny[issue] {
  resource := input.resource_blocks[_]
  resource.type == "aws_ec2_network_insights_path"

  filter_block := resource.get_block("filter_at_source")
  (filter_block == null) || not filter_block.get_attribute("source_address")

  issue := {
    ResourceID: resource.id,
    RuleID: __rego_metadata__.id,
    Message: __rego_metadata__.description
  }
}