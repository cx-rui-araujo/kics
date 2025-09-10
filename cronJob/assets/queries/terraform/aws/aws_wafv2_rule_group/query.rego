package main

__rego_metadata__ := {
  "id": "AWSWAF2_URI_FRAGMENT_NO_LOWERCASE",
  "title": "AWS WAFv2 rule group uses uri_fragment without lowercase transformation",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "platform": "terraform",
  "related_resources": ["aws_wafv2_rule_group"]
}

violation[resource] {
  input.resource_changes[_].type == "aws_wafv2_rule_group"
  change := input.resource_changes[_].change.after
  rules := change.rules
  rule := rules[_]
  byte_match := rule.statement.byte_match_statement
  byte_match.field_to_match.uri_fragment
  not lowercase_applied(byte_match.text_transformations)
  resource := rule
}

lowercase_applied(transformations) {
  some i
  transformations[i].type == "LOWER_CASE"
}