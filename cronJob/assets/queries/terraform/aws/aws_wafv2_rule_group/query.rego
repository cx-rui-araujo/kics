package terraform.aws.wafv2

deny[res] {
  # Catch aws_wafv2_rule_group using uri_fragment in field_to_match
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  rules := after.rules
  some i, j, k
  rule := rules[i]
  stmt := rule.statement[j]
  scs := stmt.size_constraint_statement
  f2m := scs.field_to_match
  f2m.uri_fragment
  res := {
    "msg": sprintf("WAFv2 rule group '%s' defines unsupported uri_fragment in field_to_match, which may be bypassed by clients.", [resource.address]),
    "resource": resource.address
  }
}
