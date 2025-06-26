package kics

violation[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  # Iterate over rules
  some i
  rule := after.rule[i]
  # Extract statement block
  statement := rule.statement
  # Check any field_to_match contains uri_fragment
  (statement.byte_match_statement.field_to_match.uri_fragment != "") ||
  (statement.sqli_match_statement.field_to_match.uri_fragment != "") ||
  (statement.xss_match_statement.field_to_match.uri_fragment != "") ||
  (statement.size_constraint_statement.field_to_match.uri_fragment != "")
  message := sprintf("aws_wafv2_rule_group '%s' uses uri_fragment in field_to_match, which is not sent to the server and may allow WAF bypass", [resource.address])
}
