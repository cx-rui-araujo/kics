package terraform.aws_wafv2_rule_group

__rego_metadata__ := {
  "id": "KICS-TF-1000",
  "title": "WAFv2 rule group should not inspect URI fragments",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

violation[resource] {
  resource := input.resource.aws_wafv2_rule_group[_]
  rule := resource.values.rule[_]
  stmt := rule.statement[_]
  # catch any byte_match or geo or xss etc statements with uri_fragment
  any_match := stmt[_]["field_to_match"][_]
  any_match.uri_fragment
}