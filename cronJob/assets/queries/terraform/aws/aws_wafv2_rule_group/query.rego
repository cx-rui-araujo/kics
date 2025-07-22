package waf

__rego_metadata__ := {
  "id": "KICS_AWS_WAFV2_URI_FRAGMENT_MATCH",
  "title": "Detect usage of uri_fragment in aws_wafv2_rule_group",
  "severity": "MEDIUM",
  "type": "MISCONF",
  "description": "AWS WAFv2 does not inspect URI fragments (they are not sent to the server), making rules with uri_fragment ineffective."
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  rules := after.rule_group.rules
  rule := rules[_]
  # Check any statement type for uri_fragment usage
  stmt := rule.statement[_]
  stmt.field_to_match.uri_fragment
}