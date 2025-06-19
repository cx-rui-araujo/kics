package main
import data.terraform.tfconfig as tfconfig

deny[resource] {
  resource := tfconfig.resources[_]
  resource.type == "aws_wafv2_rule_group"
  rule := resource.values.rule[_]
  stmt := rule.statement[_]
  bms := stmt.byte_match_statement
  frag := bms.field_to_match.uri_fragment
  frag != null
}