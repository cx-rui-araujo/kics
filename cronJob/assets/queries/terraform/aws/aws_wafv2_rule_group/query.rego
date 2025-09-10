package kics

__rego_metadata__ := {
  "id": "CUSTOM_AWS_WAF_URI_FRAGMENT",
  "title": "Invalid WAFv2 field_to_match uri_fragment",
  "type": "VULNERABILITY",
  "severity": "HIGH",
  "description": "AWS WAF cannot inspect URI fragments because they are not sent to the server, making rules matching on uri_fragment ineffective."
}

violation[resource] {
  rc := input.plan.resource_changes[_]
  rc.type == "aws_wafv2_rule_group"
  after := rc.change.after
  some i, j
  after.rules[i].statement[j].byte_match_statement.field_to_match.uri_fragment
  resource = rc.address
}