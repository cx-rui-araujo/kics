package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  statements := after.rule[*].statement
  some i
  bm := statements[i].byte_match_statement
  fm := bm.field_to_match
  fm.uri_fragment
  not fm.body
  not fm.method
  not fm.query_string
  msg := sprintf("WAFv2 rule group '%s' uses uri_fragment only in field_to_match, which can be bypassed", [resource.address])
}