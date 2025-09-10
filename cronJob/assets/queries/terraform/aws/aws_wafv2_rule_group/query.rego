package kics

__rego_metadata__ = {
  "id": "AWS125",
  "title": "Use of uri_fragment in AWS WAFv2 Rule Group",
  "severity": "MEDIUM",
  "type": "Misconfiguration"
}

violation[resource] {
  resource := input.resource_config
  resource.type == "aws_wafv2_rule_group"
  rule := resource.rule[_]
  stmt := rule.statement[_]
  ftm := stmt.field_to_match[_]
  ftm.uri_fragment
}