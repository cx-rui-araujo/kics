package terraform.kics

__rego_metadata__ := {
  "id": "AWS074",
  "title": "Missing filter_at_source.source_address in aws_ec2_network_insights_path",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[diagnostic] {
  resource := input.resource.aws_ec2_network_insights_path[_]
  not resource.values.filter_at_source
  diagnostic := {
    "message": sprintf("Resource '%s' is missing 'filter_at_source.source_address', which may allow unrestricted network paths", [resource.address]),
    "resource": resource.address
  }
}

deny[diagnostic] {
  resource := input.resource.aws_ec2_network_insights_path[_]
  some i
  resource.values.filter_at_source[i].source_address == ""
  diagnostic := {
    "message": sprintf("Resource '%s' has an empty 'filter_at_source.source_address', which may result in open ingress", [resource.address]),
    "resource": resource.address
  }
}