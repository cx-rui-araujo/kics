package main

violation[{"msg": msg, "resource": address}] {
  rc := input.resource_changes[_]
  rc.type == "aws_wafv2_rule_group"
  address := rc.address
  rule := rc.change.after.rules[_]
  stm := rule.statement[_]
  stm.field_to_match.uri_fragment
  msg := sprintf("aws_wafv2_rule_group '%s' uses uri_fragment in field_to_match, which can be bypassed as URI fragments are not sent to servers.", [address])
}
