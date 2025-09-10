package aws.wafv2

violation[alert] {
  input.resource_type == "aws_wafv2_rule_group"
  some i
  rule := input.resource_values.rules[i]
  stmt := rule.statement.byte_match_statement.field_to_match
  # Detect use of uri_fragment only without any other match fields
  stmt.uri_fragment
  not stmt.all_query_arguments
  not stmt.single_header
  not stmt.query_string
  not stmt.method
  alert := {
    "id": "KICS-9999",
    "message": "WAFv2 rule_group uses only uri_fragment in field_to_match; malicious payload in other parts may bypass WAF",
    "severity": "MEDIUM",
    "resource": input.resource_id
  }
}