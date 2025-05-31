package terraform.aws.WAFv2

violation[{"message": msg, "resource": name}] {
  some name
  rule_group := input.resource.aws_wafv2_rule_group[name]
  rule := rule_group.rule[_]
  stmt := rule.statement[_]
  stmt.field_to_match.uri_fragment
  msg := sprintf("WAFv2 rule group '%s' uses uri_fragment match which cannot inspect URL fragments, causing a blind spot.", [name])
}