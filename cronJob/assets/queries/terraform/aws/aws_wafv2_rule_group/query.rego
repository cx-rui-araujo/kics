package main

__rego_metadata__ = {
  "id": "AWSWAF2-URI-FRAGMENT-001",
  "title": "Ineffective URI fragment matching",
  "description": "Matching on URI fragment in AWS WAFv2 rules is ineffective because fragments aren’t sent to the server, leading to false sense of security.",
  "severity": "MEDIUM",
  "type": "MISCONFIGURATION"
}

violation[resource] {
  resource := input.resource
  resource.Type == "aws_wafv2_rule_group"
  rules := resource.Configuration.rule
  some i
  stmt := rules[i].statement
  byte_match := stmt.byte_match_statement
  byte_match.field_to_match.uri_fragment
}