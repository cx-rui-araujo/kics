package main

__rego_metadata__ := {
  "id": "KICS-AWS-0001",
  "title": "Detect use of uri_fragment in AWS WAFv2 Rule Group",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "category": "infrastructure"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  rules := after.rules
  some i
  rule := rules[i]
  statements := rule.statement
  some j
  stmt := statements[j]
  bms := stmt.byte_match_statement
  some k
  bm := bms[k]
  field_to_match := bm.field_to_match
  some f
  field_to_match[f].uri_fragment
  resource := after
}