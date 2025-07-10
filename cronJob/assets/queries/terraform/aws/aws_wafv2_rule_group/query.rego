package kics

__rego_kics_metadata__ = {
  "id": "AWS009",
  "title": "WAFv2 rule_group should not use uri_fragment",
  "severity": "MEDIUM",
  "type": "MISCONFIGURATION",
  "description": "uri_fragment in field_to_match cannot be enforced by WAF as HTTP fragments are not sent to the server.",
  "category": "Security"
}

violation[{"msg": msg, "resource": resource_name}] {
  resource_name = sprintf("%s.%s", [resource_type, name])
  resource_type, name = input.resource.aws_wafv2_rule_group[name][_]
  some rule_index
  rule = input.resource.aws_wafv2_rule_group[name].rule[rule_index]
  some stmt_index
  stmt = rule.statement[stmt_index]
  some byte_index
  byte = stmt.byte_match_statement[byte_index]
  some field_index
  field = byte.field_to_match[field_index]
  field.uri_fragment
  msg = sprintf("WAFv2 rule_group '%s' uses uri_fragment which is not enforced by WAF.", [name])
}