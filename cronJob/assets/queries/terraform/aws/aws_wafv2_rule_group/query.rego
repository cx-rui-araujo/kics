package main

__rego_metadata__ = {
  "id": "KICS-AWS-URI-FRAGMENT-1",
  "title": "AWS WAFv2 Rule Group uses uri_fragment in field_to_match",
  "severity": "MEDIUM",
  "category": "security",
}

deny[violation] {
  resource := input.resource
  resource.type == "aws_wafv2_rule_group"
  # iterate over all rule blocks
  rules := resource.values.rule[_]
  stmt := rules.statement[_]
  # check for byte_match_statement with uri_fragment
  bms := stmt.byte_match_statement
  bms.field_to_match.uri_fragment
  violation := {
    "msg": sprintf("Resource '%s' uses uri_fragment in field_to_match, which may allow bypass of fragment-based attacks.", [resource.name]),
    "resource": resource.name,
  }
}