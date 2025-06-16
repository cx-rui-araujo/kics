package kics

import data.terraform as tf

__rego_metadata__ := {
  "id": "KICS-999",
  "title": "Ineffective usage of uri_fragment in AWS WAFv2 rule",
  "severity": "LOW",
  "category": "Misconfiguration"
}

violation[{
  "msg": msg,
  "resource": resource_name
}] {
  resource := tf.resource[res_index]
  resource.type == "aws_wafv2_rule_group"

  # iterate through rules and statements
  some r_i, s_i
  rule := resource.values.rule[r_i]
  stmt := rule.statement[s_i]

  # detect uri_fragment usage
  stmt.byte_match_statement.field_to_match.uri_fragment

  resource_name := resource.name
  msg := sprintf("Resource '%s' uses 'uri_fragment' in field_to_match, which is ineffective as fragments are not sent to the server.", [resource_name])
}