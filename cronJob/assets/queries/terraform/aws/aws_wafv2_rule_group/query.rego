package terraform.aws.WAF2.RuleGroup

violation[rule] {
  resource := terraform.resource.aws_wafv2_rule_group[_]
  resource.statement[_].field_to_match.uri_fragment
  rule := {
    "resource": resource.address,
    "message": "Using uri_fragment in field_to_match is ineffective because URI fragments are not sent to the server, allowing bypass."
  }
}