package main

deny[msg] {
  resource := input.resource
  resource.type == "aws_wafv2_rule_group"
  rules := resource.values.rules
  rule := rules[_]
  stmt := rule.statement[_]
  sqli := stmt.sqli_match_statement
  fm := sqli.field_to_match[_]
  fm.uri_fragment
  msg := sprintf("aws_wafv2_rule_group '%v' uses uri_fragment in field_to_match, which AWS WAF does not inspect and may allow bypass", [resource.id])
}