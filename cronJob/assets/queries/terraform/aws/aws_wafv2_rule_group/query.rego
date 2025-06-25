package main

import data

violation[{"msg": msg, "resource": res.Name}] {
  res := data.resource_blocks[_]
  res.Type == "aws_wafv2_rule_group"
  fragments := res.GetBlocks("statement")[*]
    .GetBlocks("byte_match_statement")[*]
    .GetBlocks("field_to_match")[*]
    .GetBlocks("uri_fragment")
  count(fragments) > 0
  msg := sprintf("Resource '%s' includes 'uri_fragment', which AWS WAFv2 cannot inspect, leading to potential bypass.", [res.Name])
}