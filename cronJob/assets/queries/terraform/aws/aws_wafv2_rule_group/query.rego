package main

import data.tfconfig as tfconfig

denied[message] {
  resource := tfconfig.resource["aws_wafv2_rule_group"][name]
  rule := resource.rule[_]
  byte_match := rule.statement.byte_match_statement
  byte_match.field_to_match.uri_fragment
  message := sprintf("Resource '%s' uses uri_fragment in field_to_match, which may allow attackers to bypass filters.", [name])
}