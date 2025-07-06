package aws_wafv2

# Deny usage of uri_fragment in aws_wafv2_rule_group as it is never sent to servers and can lead to bypass

deny[msg] {
  resource := input.resource
  resource.type == "aws_wafv2_rule_group"
  has_uri_fragment(resource.config.rule)
  msg = sprintf("aws_wafv2_rule_group '%v' uses uri_fragment in field_to_match which is not processed by AWS WAF and can be bypassed", [resource.config.name[0]])
}

# Traverse rules to find any byte_match_statement using uri_fragment
has_uri_fragment(rules) {
  some i
  rule := rules[i]
  contains_fragment(rule.statement)
}

contains_fragment(stmt) {
  stmt.byte_match_statement.field_to_match.uri_fragment
}
contains_fragment(stmt) {
  some j
  contains_fragment(stmt.and_statement.statements[j])
}
contains_fragment(stmt) {
  some j
  contains_fragment(stmt.or_statement.statements[j])
}
contains_fragment(stmt) {
  contains_fragment(stmt.not_statement.statement)
}