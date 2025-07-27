package main

__rego_meta__ = {
  "id": "AWS_WAFV2_001",
  "title": "Avoid matching on uri_fragment in WAFv2 rule group",
  "severity": "LOW",
  "type": "VULNERABILITY",
  "description": "Matching on uri_fragment can be bypassed because URI fragments are not sent to the server and thus not reliably inspected by WAF.",
  "reference_id": "AWS.WAFV2.URI_FRAGMENT",
  "recommended_actions": "Remove the uri_fragment block from field_to_match or use other fields such as uri_path or query_string for reliable inspection."
}

import data.terraform.resources

violation[resource] {
  resource := resources[_]
  resource.type == "aws_wafv2_rule_group"
  rule := resource.values.rule[_]
  stmt := rule.statement[_]
  rps := stmt.regex_pattern_set_reference_statement
  rps.field_to_match[0].uri_fragment
}
