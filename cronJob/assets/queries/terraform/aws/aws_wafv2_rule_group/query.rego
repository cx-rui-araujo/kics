package aws_wafv2_rule_group

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  change := resource.change.after
  rule := change.rules[_]
  stmt := rule.statement
  fm := stmt.field_to_match
  fm.uri_fragment
  not fm.query_string
}