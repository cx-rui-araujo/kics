package kics

import data.tfplan

# Deny usage of uri_fragment in WAFv2 rule_group as fragments are never sent in HTTP requests
violation[message] {
  resource := data.tfplan.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  rule := resource.change.after.rule[_]
  stmt := rule.statement[_]
  stmt.field_to_match.uri_fragment
  message := sprintf("aws_wafv2_rule_group '%s' uses ineffective uri_fragment field_to_match", [resource.name])
}
