package main

# KICS query to detect uri_fragment usage in aws_wafv2_rule_group

deny[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  # Navigate to each rule in the rule group
  rule := resource.change.after.rules[_]
  # Search any statement for field_to_match with uri_fragment
  stmt := rule.statement[_]
  match := stmt.field_to_match
  match.uri_fragment
  violation := {
    "message": "Using uri_fragment in field_to_match for aws_wafv2_rule_group is ineffective; URI fragments are not sent in requests and can be bypassed",
    "resource": resource.address
  }
}