package terraform.analysis

__rego_metadata__ := {
  "id": "KICS_AWS_WAFV2_URI_FRAGMENT_MATCH",
  "title": "AWS WAFv2 Rule Group should not match on uri_fragment",
  "severity": "LOW",
  "type": "VULNERABILITY",
  "confidence": "HIGH"
}

violation[{"msg": msg, "resource": rc.address}] {
  rc := input.resource_changes[_]
  rc.type == "aws_wafv2_rule_group"
  rc.change.after.rules[_].statement.byte_match_statement.field_to_match.uri_fragment
  msg := sprintf("Resource '%s' uses uri_fragment in field_to_match, which is not sent to the server and may bypass WAF rules", [rc.address])
}