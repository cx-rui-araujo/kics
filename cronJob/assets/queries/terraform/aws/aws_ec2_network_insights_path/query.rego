package kics

__rego_meta__ := {
  "id": "AWS009",
  "title": "Ensure aws_ec2_network_insights_path filter_at_source.source_address is specified",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "docs": {
    "description": "A missing filter_at_source.source_address may allow unintended traffic to be evaluated, potentially exposing connectivity paths.",
    "recommendation": "Specify a source_address in filter_at_source to restrict the scope of the Network Insights Path."  
  }
}

deny[resp] {
  input.kind == "resource"
  input.provider == "aws"
  input.type == "aws_ec2_network_insights_path"
  source_filter := input.attributes.filter_at_source
  not source_filter[_].source_address
  resp := {
    "resource": input.metadata.name,
    "message": "filter_at_source.source_address is not specified"
  }
}