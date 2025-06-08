package tf/aws/wafv2/rule_group

__rego_metadata__ := {"id":"AWS122","title":"Ensure WAFv2 Rule Group does not use URI fragment in field_to_match","severity":"MEDIUM","type":"VULNERABILITY"}

violation[resource] {
  resource := tfconfig.resources.aws_wafv2_rule_group[_]
  rule := resource.values.rules[_]
  # Flag presence of uri_fragment which is client-side only and ineffective
  rule.statement.byte_match_statement.field_to_match.uri_fragment
}