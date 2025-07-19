package terraform.aws.wafv2

# This query flags WAFv2 rule groups using uri_fragment in field_to_match,
# which is never sent to the server and results in ineffective rules.
violation[{
  "resource": resource.address,
  "message": "aws_wafv2_rule_group uses uri_fragment in field_to_match, which is never inspected by AWS WAF and may lead to bypassable rules."
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_wafv2_rule_group"
  after := resource.change.after
  rule := after.rule[_]
  stmt := rule.statement[_]
  stmt.field_to_match.uri_fragment
}