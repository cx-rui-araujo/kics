package terraform.aws.wafv2.rulegroup.uri_fragment

__rego_metadata__ = {
  "id": "AWS.WAFV2.RuleGroup.FieldToMatch.UriFragment",
  "title": "Ineffective use of uri_fragment in aws_wafv2_rule_group field_to_match",
  "severity": "MEDIUM",
  "type": "Misconfiguration",
  "category": "security"
}

violation[issue] {
  resource := input.resource
  resource.type == "aws_wafv2_rule_group"
  some i, j
  rule := resource.values.rule_group.rules[i]
  statement := rule.statement[j]
  field := statement.regex_pattern_set_reference_statement.field_to_match[j]
  field.uri_fragment
  issue := {
    "resource": resource.id,
    "message": "The 'uri_fragment' field_to_match is ineffective because HTTP fragments are not sent to the server, disabling this WAF rule's intended protection."
  }
}