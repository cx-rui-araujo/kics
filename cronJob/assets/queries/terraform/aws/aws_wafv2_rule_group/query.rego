package main

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  some i
  # Detects any SQLi match statement using uri_fragment
  s := resource.change.after.rule[i].statement.sqli_match_statement
  s.field_to_match.uri_fragment
}