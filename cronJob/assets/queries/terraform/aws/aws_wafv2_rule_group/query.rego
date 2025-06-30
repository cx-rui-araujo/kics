package main

violation[{"message": msg, "resource": address, "severity": "LOW"}] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  address := resource.address
  rule := resource.change.after.rules[_]
  stmt := rule.statement.byte_match_statement
  stmt.field_to_match.uri_fragment
  msg := sprintf("WAFv2 rule group '%s' uses uri_fragment match which is never sent to servers and can be bypassed", [address])
}