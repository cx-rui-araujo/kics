package kics

import data

deny[resource] {
  resource := input.resource
  resource.type == "aws_wafv2_rule_group"
  some i
  rule := resource.values.rules[i]
  # Check any statement nesting for uri_fragment
  uri_match(rule)
}

uri_match(stmt) {
  # sqli_match_statement example, extend to any statement type
  stmt.sqli_match_statement.field_to_match.uri_fragment
}
