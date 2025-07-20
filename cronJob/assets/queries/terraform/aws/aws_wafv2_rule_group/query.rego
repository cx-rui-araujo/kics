package terraform.aws

deny[rule] {
  resource := input.Resources[_]
  resource.Type == "aws_wafv2_rule_group"
  rule := resource.Values.rule[_]
  stmt := rule.statement[_]
  field := stmt.byte_match_statement.field_to_match
  field.uri_fragment
}