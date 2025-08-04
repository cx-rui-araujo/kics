package waf2

import data.terraform.resource_changes

violation[rc.address] {
  rc := resource_changes[_]
  rc.type == "aws_wafv2_rule_group"
  rules := rc.change.after.rules[_]
  stm := rules.statement[_]
  scs := stm.size_constraint_statement
  scs.field_to_match.uri_fragment
}