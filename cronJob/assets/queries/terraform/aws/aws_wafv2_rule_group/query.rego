package terraform_audit

# AWS004: Disallow use of uri_fragment in aws_wafv2_rule_group field_to_match

default deny = false

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  # iterate rules blocks
  rules := after.rule
  rule := rules[_]
  # descend into statements to find any field_to_match.uri_fragment
  stmt := rule.statement[_]
  # direct or nested statements can also exist, but we look for uri_fragment key
  stmt.field_to_match.uri_fragment
  msg = sprintf("Resource '%v' defines field_to_match.uri_fragment, which is ineffective since HTTP fragments are not sent to servers.", [resource.address])
}