package main

__rego_metadata__ := {
  "id": "KICS_AWS_WAFV2_URI_FRAGMENT",
  "title": "Ineffective URI Fragment field_to_match in AWS WAFv2 rule group",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

violation[rule] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  change := resource.change.after
  some i
  change.rules[i].statement.byte_match_statement.field_to_match.uri_fragment
  rule := {
    "rule_group": change.name,
    "rule_index": i
  }
}
