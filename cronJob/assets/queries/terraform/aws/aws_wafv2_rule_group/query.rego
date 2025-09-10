package waf_v2

violation[resource] {
  resource := input.resources[_]
  resource.type == "aws_wafv2_rule_group"
  # check any rule statement for uri_fragment
  some r
  rule := resource.values.rule[r]
  some s
  stmt := rule.statement.or_statement.statements[s]
  # catch byte_match, size_constraint, xss, or sqli using uri_fragment
  (
    stmt.byte_match_statement.field_to_match.uri_fragment
  )
}