package kics

violation[{"id": id, "msg": msg, "resource": resource}] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  rule := resource.change.after.rules[_]
  statement := rule.statement
  # detect usage of uri_fragment in field_to_match
  field := statement.sqli_match_statement.field_to_match
  field.uri_fragment
  id = "WAFV2_UNSUPPORTED_FIELD_URI_FRAGMENT"
  msg = sprintf("WAFv2 rule '%s' uses 'uri_fragment' which is not inspected by AWS WAF and can be bypassed.", [resource.name])
}  