package main
import data.terraform.plan as plan

__rego_metadata__ := {
  "id": "KICS-AWS-URI-FRAGMENT-001",
  "title": "AWS WAFv2 Rule Group using uri_fragment in field_to_match",
  "severity": "MEDIUM",
  "type": "MISCONFIGURATION",
}

violation[message] {
  resource := plan.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  some i
  after.rules[i].statement.byte_match_statement.field_to_match.uri_fragment
  message := sprintf("aws_wafv2_rule_group '%s' uses uri_fragment in field_to_match, which may bypass full URI inspection.", [resource.address])
}
