package kics

import data

__rego_metadata__ := {
  "id": "KICS-AWS-URI-FRAGMENT-0001",
  "title": "Do not use uri_fragment in aws_wafv2_rule_group",
  "description": "Matching on URI fragments is ineffective because fragments are not sent in HTTP requests to the server, leading to false negatives and a false sense of security.",
  "severity": "LOW",
  "recommendation": "Remove the uri_fragment match block from your aws_wafv2_rule_group to ensure rules correctly match client requests.",
  "platform": "Terraform",
  "version": "1.0.0"
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  # iterate over rules in the rule_group
  some i
  rule := after.rule_group[0].rules[i]
  stmts := rule.statement
  # detect any field_to_match.uri_fragment usage
  stmts.size_constraint_statement.field_to_match.uri_fragment
  res := {
    "resource": resource.address,
    "message": "Found uri_fragment in field_to_match, which will never match any request fragments."
  }
}