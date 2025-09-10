package main

__on_terraform

violation[{"resource": resource.address, "rule_name": rule.name, "msg": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  rule := resource.change.after.rules[_]
  field := rule.statement.sqli_match_statement.field_to_match.uri_fragment
  field
  msg := "The use of uri_fragment in AWS WAFv2 rule is ineffective since URI fragments are not part of HTTP requests."
}